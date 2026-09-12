#include "qt/docking/dock_host.hpp"

#include "qt/docking/hub_dock.hpp"
#include "qt/docking/view_placeholder.hpp"
#include "qt/explorer/exchange/open_dispatch.hpp"
#include "qt/registry/view_visibility.hpp"
#include "qt/layout/workspace_persistence.hpp"
#include "qt/layout/monitor_rehome.hpp"
#include "qt/layout/workspace_operations.hpp"

#include "core/disasm/disasm_view.hpp"
#include "core/session/analysis_session.hpp"
#include "helpers/diag_log.hpp"
#include "qt/theme/aida_theme_controller.hpp"
#include "qt/widgets/aida_state_view.hpp"

#include <DockManager.h>
#include <DockWidget.h>
#include <DockAreaWidget.h>
#include <DockContainerWidget.h>
#include <DockSplitter.h>
#include <FloatingDockContainer.h>
#include <ads_globals.h>

#include <QEvent>
#include <QMainWindow>
#include <QScreen>
#include <QSplitter>
#include <QSplitterHandle>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <limits>
#include <utility>

namespace aida::qt::docking {

namespace {

class SplitterLockFilter : public QObject {
public:
    explicit SplitterLockFilter(QObject* parent = nullptr)
        : QObject(parent) {}

    std::function<bool()> locked;

    bool eventFilter(QObject* watched, QEvent* event) override {
        if (!locked || !locked())
            return false;
        switch (event->type()) {
        case QEvent::MouseButtonPress:
        case QEvent::MouseButtonRelease:
        case QEvent::MouseButtonDblClick:
        case QEvent::MouseMove:
            return dynamic_cast<QSplitterHandle*>(watched) != nullptr;
        default:
            return false;
        }
    }
};

bool is_disassembly_side_instance(const registry::view_instance_id_t& id) noexcept {
    if (id.view.value() != "document.disassembly")
        return false;
    const std::string& key = id.instance.value();
    return key == "side.1" || key == "side.2" || key == "side.3";
}

bool parse_code_group_key(const registry::stable_view_instance_key_t& key,
                          std::uint32_t& output) noexcept {
    constexpr const char* prefix = "group.";
    const std::string& value = key.value();
    if (value.compare(0, std::strlen(prefix), prefix) != 0)
        return false;
    const char* first = value.c_str() + std::strlen(prefix);
    if (*first == '\0')
        return false;
    char* end = nullptr;
    const unsigned long parsed = std::strtoul(first, &end, 10);
    if (!end || *end != '\0' ||
        parsed > (std::numeric_limits<std::uint32_t>::max)())
        return false;
    output = static_cast<std::uint32_t>(parsed);
    return true;
}

}

AidaDockHost::AidaDockHost(QMainWindow* window, QObject* parent)
    : QObject(parent), window_(window) {
    registry_ = new registry::qt_view_registry_t(this);

    manager_ = new ads::CDockManager(window_);
    manager_->setStyleSheet(QString());
    diag::log_tagged_critical_fmt("qt_dock_host",
        "dock_manager_created manager=0x%llX focus_highlighting=%d tid=%lu",
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(manager_)),
        ads::CDockManager::testConfigFlag(ads::CDockManager::FocusHighlighting) ? 1 : 0,
        static_cast<unsigned long>(::GetCurrentThreadId()));

    empty_state_ = new QWidget(manager_);
    empty_state_->setObjectName(QStringLiteral("aida.dock_host.empty_state"));
    {
        auto* empty_layout = new QVBoxLayout(empty_state_);
        empty_layout->setContentsMargins(0, 0, 0, 0);
        empty_layout->addStretch(1);
        auto* state_view = new widgets::AidaStateView(widgets::AidaStateView::State::Empty,
            QStringLiteral("No views open"),
            QStringLiteral("Open views from the View menu or the activity rail to build your workspace."),
            empty_state_);
        state_view->setActionLabel(QStringLiteral("Open Start Center"));
        connect(state_view, &widgets::AidaStateView::actionTriggered, this, [this] {
            static_cast<void>(open_or_focus(registry::stable_view_id_t("view.start_center")));
        });
        state_view->setFixedSize(state_view->sizeHint());
        empty_layout->addWidget(state_view, 0, Qt::AlignHCenter);
        empty_layout->addStretch(1);
        connect(&theme::AidaThemeController::instance(),
                &theme::AidaThemeController::themeGenerationChanged,
                state_view, [state_view] {
            state_view->setFixedSize(state_view->sizeHint());
        });
    }
    empty_state_->hide();
    manager_->installEventFilter(this);

    registry_->set_workspace_available_hook([] {
        return static_cast<bool>(disasm_view::capture_selected_workspace());
    });
    registry_->set_image_available_hook([] {
        return aida::qt::explorer::image_active();
    });
    registry_->set_hub_activation_hook([this](registry::hub_kind_t hub, int subview) {
        activate_hub_subview(hub, subview);
    });
    registry_->set_host_hooks({
        [this](const registry::qt_view_descriptor_t& descriptor,
               const registry::view_instance_id_t& id,
               const std::string& display_name) {
            return host_open(descriptor, id, display_name);
        },
        [this](const registry::view_instance_id_t& id) { return host_focus(id); },
        [this](const registry::view_instance_id_t& id) { return host_close(id); },
        [this](const registry::view_instance_id_t& id) { return host_erase(id); },
        [this](const registry::view_instance_id_t& id) { host_deactivate(id); }
    });
    catalog_registered_ = registry_->register_catalog(&placeholder_view_factory) ==
        registry::k_catalog_size;
    if (!catalog_registered_)
        diag::log_tagged_critical("qt_dock_host", "catalog_registration_incomplete");

    work_indicator_hook_ = [] {
        return analysis_session::session_count() != 0;
    };

    auto* lock_filter = new SplitterLockFilter(this);
    lock_filter->locked = [this] { return layout_locked_; };
    splitter_lock_filter_ = lock_filter;

    connect(manager_, &ads::CDockManager::focusedDockWidgetChanged,
            this, [this](ads::CDockWidget*, ads::CDockWidget* now) {
                handle_focused_dock_changed(now);
            });
    connect(manager_, &ads::CDockManager::dockWidgetAdded,
            this, [this](ads::CDockWidget*) { mark_dirty("dock_added"); });
    connect(manager_, &ads::CDockManager::dockWidgetRemoved,
            this, [this](ads::CDockWidget*) { mark_dirty("dock_removed"); });
    connect(manager_, &ads::CDockManager::dockAreaCreated,
            this, [this](ads::CDockAreaWidget*) {
                if (!restoring_) {
                    refresh_splitter_locks();
                    wire_layout_watchers();
                }
                mark_dirty("area_created");
            });
    connect(manager_, &ads::CDockManager::floatingWidgetCreated,
            this, [this](ads::CFloatingDockContainer*) {
                if (!restoring_)
                    wire_layout_watchers();
                mark_dirty("floating_created");
            });
    connect(manager_, &ads::CDockManager::restoringState,
            this, [this] { restoring_ = true; });
    connect(manager_, &ads::CDockManager::stateRestored,
            this, [this] {
                restoring_ = false;
                const std::uint64_t started = ::GetTickCount64();
                reconcile_from_manager();
                const std::uint64_t reconciled = ::GetTickCount64();
                apply_surface_state();
                const std::uint64_t surfaced = ::GetTickCount64();
                refresh_splitter_locks();
                wire_layout_watchers();
                const std::uint64_t watched = ::GetTickCount64();
                mark_dirty("state_restored");
                diag::log_tagged_fmt("qt_dock_host",
                    "state_restored_handler reconcile_ms=%llu surface_ms=%llu locks_watchers_ms=%llu total_ms=%llu",
                    static_cast<unsigned long long>(reconciled - started),
                    static_cast<unsigned long long>(surfaced - reconciled),
                    static_cast<unsigned long long>(watched - surfaced),
                    static_cast<unsigned long long>(watched - started));
            });

    visibility_ = new registry::ViewVisibilityController(registry_, this);
    registry::ViewVisibilityController::view_actions_t actions;
    actions.open = [this](const registry::view_instance_id_t& id) {
        return registry_->open(id, registry_->context());
    };
    actions.close = [this](const registry::view_instance_id_t& id) {
        return registry_->close(id);
    };
    actions.open_or_focus = [this](const registry::stable_view_id_t& id) {
        return open_or_focus(id);
    };
    actions.suppress_start_center_auto_open = [this] {
        start_center_auto_open_ = false;
    };
    visibility_->set_view_actions(std::move(actions));

    persistence_ = new layout::WorkspacePersistenceController(this, registry_, this);
    visibility_->set_active_context_provider([this] {
        return std::make_pair(persistence_->active_preset(),
                              persistence_->active_identity_key());
    });
    connect(visibility_, &registry::ViewVisibilityController::visibilityCaptured,
            this, [this] { mark_dirty("visibility_captured"); });

    rehome_ = new layout::MonitorRehomeController(window_, manager_, this);
    connect(rehome_, &layout::MonitorRehomeController::rehomed,
            this, [this] { mark_dirty("floating_rehomed"); });
}

AidaDockHost::~AidaDockHost() = default;

registry::view_operation_result_t AidaDockHost::install_view_factory(
    const registry::stable_view_id_t& id,
    registry::qt_view_factory_t factory,
    std::optional<registry::content_policy_t> policy) {
    const registry::stable_view_id_t canonical = registry_->canonical_view_id(id);
    const auto result = registry_->install_view_factory(canonical, std::move(factory), policy);
    if (!result.ok())
        return result;
    const auto* descriptor = registry_->find_descriptor(canonical);
    if (!descriptor)
        return result;
    if (descriptor->hub != registry::hub_kind_t::none) {
        if (auto* hub = hub_widget(descriptor->hub))
            hub->rebuild_page(descriptor->hub_subview);
        return result;
    }
    const auto instance = registry_->instance_for(canonical);
    if (ads::CDockWidget* dock = dock_for(instance)) {
        const auto found = docks_.find(dock->objectName().toStdString());
        if (found != docks_.end() && !found->second.content_disposed &&
            !found->second.content_pending && dock->widget() != nullptr) {
            if (QWidget* previous = dock->takeWidget()) {
                QWidget* replacement = create_content(*descriptor, instance, dock);
                dock->setWidget(replacement, ads::CDockWidget::ForceNoScrollArea);
                previous->deleteLater();
            }
        }
    }
    return result;
}

bool AidaDockHost::is_ported(const registry::stable_view_id_t& id) const {
    return registry_->is_ported(id);
}

void AidaDockHost::mark_dirty(const char* reason) {
    if (restoring_)
        return;
    update_empty_state();
    diag::log_tagged_fmt("qt_dock_host", "layout_dirty reason=%s tid=%lu",
        reason ? reason : "unspecified",
        static_cast<unsigned long>(::GetCurrentThreadId()));
    Q_EMIT layoutDirty();
}

void AidaDockHost::update_empty_state() {
    if (!empty_state_ || !manager_)
        return;
    bool any_open = false;
    const QMap<QString, ads::CDockWidget*> docks = manager_->dockWidgetsMap();
    for (auto iterator = docks.begin(); iterator != docks.end(); ++iterator) {
        ads::CDockWidget* dock = iterator.value();
        if (dock && !dock->isClosed()) {
            any_open = true;
            break;
        }
    }
    if (any_open == (empty_state_->isHidden()))
        return;
    empty_state_->setVisible(!any_open);
    if (!any_open) {
        position_empty_state();
        empty_state_->raise();
    }
}

void AidaDockHost::position_empty_state() {
    if (empty_state_ && manager_)
        empty_state_->setGeometry(manager_->rect());
}

bool AidaDockHost::eventFilter(QObject* watched, QEvent* event) {
    if (watched == manager_ && event && event->type() == QEvent::Resize)
        position_empty_state();
    return QObject::eventFilter(watched, event);
}

QWidget* AidaDockHost::create_content(const registry::qt_view_descriptor_t& descriptor,
                                      const registry::view_instance_id_t& instance,
                                      QWidget* parent) {
    QWidget* content = nullptr;
    try {
        if (descriptor.factory)
            content = descriptor.factory(parent, instance);
    } catch (const std::exception& exception) {
        diag::log_tagged_critical_fmt("qt_dock_host",
            "view_factory_exception view=%s detail=%s",
            descriptor.id.c_str(), exception.what());
    } catch (...) {
        diag::log_tagged_critical_fmt("qt_dock_host",
            "view_factory_exception view=%s detail=unknown",
            descriptor.id.c_str());
    }
    if (!content) {
        diag::log_tagged_critical_fmt("qt_dock_host",
            "view_factory_null view=%s fallback=placeholder",
            descriptor.id.c_str());
        content = new AidaViewPlaceholder(descriptor.id.value(), parent);
    }
    const int min_width = static_cast<int>(descriptor.minimum_size.width);
    const int min_height = static_cast<int>(descriptor.minimum_size.height);
    if (min_width >= 1 && min_height >= 1)
        content->setMinimumSize(min_width, min_height);
    return content;
}

ads::CDockWidget* AidaDockHost::create_dock(const registry::qt_view_descriptor_t& descriptor,
                                            const registry::view_instance_id_t& id,
                                            const std::string& display_name,
                                            bool defer_content) {
    const QString title = QString::fromStdString(display_name.empty()
        ? descriptor.display_name : display_name);
    auto* dock = new ads::CDockWidget(manager_, title);
    dock->setObjectName(QString::fromStdString(registry::dock_object_name(id)));
    dock->setFeatures(ads::CDockWidget::DockWidgetClosable |
        ads::CDockWidget::DockWidgetMovable |
        ads::CDockWidget::DockWidgetFloatable |
        ads::CDockWidget::DockWidgetFocusable |
        ads::CDockWidget::CustomCloseHandling);
    dock->setProperty("aida.view", QString::fromStdString(id.view.value()));
    dock->setProperty("aida.instance", QString::fromStdString(id.instance.value()));
    QWidget* content = nullptr;
    std::uint64_t content_elapsed_ms = 0;
    if (defer_content) {
        content = new QWidget(dock);
        content->setObjectName(QStringLiteral("aida.view_deferred"));
    } else {
        const std::uint64_t content_started = ::GetTickCount64();
        content = create_content(descriptor, id, dock);
        content_elapsed_ms = ::GetTickCount64() - content_started;
    }
    dock->setWidget(content, ads::CDockWidget::ForceNoScrollArea);
    wire_dock(dock, id);
    dock_record_t record;
    record.instance = id;
    record.content_pending = defer_content;
    docks_[dock->objectName().toStdString()] = record;
    if (const auto* surface = surfaces_.find(id); surface && surface->pinned)
        apply_pin(dock, true);
    diag::log_tagged_fmt("qt_dock_host",
        "dock_created object=%s role=%u policy=%u deferred=%d content_elapsed_ms=%llu",
        dock->objectName().toUtf8().constData(),
        static_cast<unsigned>(descriptor.role),
        static_cast<unsigned>(descriptor.content_policy),
        defer_content ? 1 : 0,
        static_cast<unsigned long long>(content_elapsed_ms));
    return dock;
}

bool AidaDockHost::realize_deferred_content(ads::CDockWidget* dock, dock_record_t& record) {
    if (!dock || !record.content_pending)
        return false;
    const auto* descriptor = registry_->find_descriptor(record.instance.view);
    if (!descriptor) {
        record.content_pending = false;
        return false;
    }
    const std::uint64_t started = ::GetTickCount64();
    QWidget* previous = dock->takeWidget();
    QWidget* content = create_content(*descriptor, record.instance, dock);
    dock->setWidget(content, ads::CDockWidget::ForceNoScrollArea);
    if (previous)
        previous->deleteLater();
    record.content_pending = false;
    record.content_disposed = false;
    diag::log_tagged_fmt("qt_dock_host",
        "dock_content_realized object=%s elapsed_ms=%llu",
        dock->objectName().toUtf8().constData(),
        static_cast<unsigned long long>(::GetTickCount64() - started));
    return true;
}

void AidaDockHost::wire_dock(ads::CDockWidget* dock, const registry::view_instance_id_t& id) {
    connect(dock, &ads::CDockWidget::closeRequested, this, [this, id] {
        static_cast<void>(close_instance(id));
    });
    connect(dock, &ads::CDockWidget::viewToggled, this,
            [this, dock, id](bool open) {
                const auto found = docks_.find(dock->objectName().toStdString());
                if (found == docks_.end())
                    return;
                if (open) {
                    if (restoring_)
                        return;
                    const auto* descriptor = registry_->find_descriptor(id.view);
                    if (descriptor)
                        ensure_content_for_open(dock, *descriptor, id, found->second);
                    registry_->sync_instance_visibility(id, true, false);
                    mark_dirty("dock_opened");
                    return;
                }
                if (restoring_)
                    return;
                if (!found->second.content_disposed)
                    dispose_content_for_close(dock, found->second);
                registry_->sync_instance_visibility(id, false, true);
                mark_dirty("dock_closed");
            });
    connect(dock, &ads::CDockWidget::visibilityChanged, this,
            [this](bool) { mark_dirty("dock_visibility"); });
    connect(dock, &ads::CDockWidget::topLevelChanged, this,
            [this](bool) { mark_dirty("dock_top_level"); });
}

void AidaDockHost::wire_hub_dock(ads::CDockWidget* dock, registry::hub_kind_t hub) {
    connect(dock, &ads::CDockWidget::closeRequested, this, [this, hub] {
        const auto* surface = surfaces_.find_hub(hub);
        if (surface && surface->pinned) {
            diag::log_tagged_fmt("qt_dock_host",
                "hub_close_rejected hub=%s reason=pinned", registry::hub_kind_name(hub));
            return;
        }
        if (ads::CDockWidget* hub_dock_ptr = hub_dock(hub))
            hub_dock_ptr->closeDockWidget();
    });
    connect(dock, &ads::CDockWidget::viewToggled, this,
            [this, hub](bool open) {
                if (restoring_)
                    return;
                const registry::hub_kind_t hub_kind = hub;
                std::vector<registry::stable_view_id_t> members;
                registry_->for_each_descriptor(
                    [&](const registry::qt_view_descriptor_t& descriptor) {
                        if (descriptor.hub == hub_kind)
                            members.push_back(descriptor.id);
                    });
                if (open) {
                    if (auto* widget = hub_widget(hub))
                        widget->ensure_current_page();
                    const auto active = registry_->hub_active_view(hub);
                    for (const auto& member : members) {
                        const bool is_active = active && *active == member;
                        registry_->sync_instance_visibility(
                            registry::view_instance_id_t{member,
                                registry::stable_view_instance_key_t{}},
                            is_active, false);
                    }
                    mark_dirty("hub_opened");
                    return;
                }
                const auto active = registry_->hub_active_view(hub);
                for (const auto& member : members) {
                    const registry::view_instance_id_t instance{member,
                        registry::stable_view_instance_key_t{}};
                    const bool record_history = active && *active == member &&
                        registry_->is_open(instance);
                    registry_->sync_instance_visibility(instance, false, record_history);
                }
                mark_dirty("hub_closed");
            });
    connect(dock, &ads::CDockWidget::visibilityChanged, this,
            [this](bool) { mark_dirty("hub_visibility"); });
    connect(dock, &ads::CDockWidget::topLevelChanged, this,
            [this](bool) { mark_dirty("hub_top_level"); });
    if (auto* widget = hub_widget(hub)) {
        connect(widget, &AidaHubWidget::subviewActivated, this,
                [this, hub](int subview) {
                    registry_->note_hub_subview(hub, subview);
                    surfaces_.set_hub_subview(hub, subview);
                    if (const auto active = registry_->hub_active_view(hub)) {
                        if (const auto* descriptor = registry_->find_descriptor(*active)) {
                            if (ads::CDockWidget* dock = hub_dock(hub))
                                dock->setWindowTitle(QString::fromStdString(
                                    descriptor->display_name));
                        }
                    }
                    mark_dirty("hub_subview");
                });
    }
}

ads::CDockWidget* AidaDockHost::dock_for(const registry::view_instance_id_t& id) const {
    return manager_->findDockWidget(QString::fromStdString(registry::dock_object_name(id)));
}

ads::CDockWidget* AidaDockHost::ensure_dock(const registry::qt_view_descriptor_t& descriptor,
                                            const registry::view_instance_id_t& id,
                                            const std::string& display_name) {
    if (ads::CDockWidget* existing = dock_for(id)) {
        if (!display_name.empty())
            existing->setWindowTitle(QString::fromStdString(display_name));
        return existing;
    }
    auto* dock = create_dock(descriptor, id, display_name);
    place_new_dock(dock, descriptor);
    return dock;
}

int AidaDockHost::default_area_for(const registry::qt_view_descriptor_t& descriptor) const {
    switch (descriptor.role) {
    case registry::view_presentation_role_t::document:
        return ads::CenterDockWidgetArea;
    case registry::view_presentation_role_t::inspector:
        return ads::RightDockWidgetArea;
    case registry::view_presentation_role_t::bottom_panel:
        return ads::BottomDockWidgetArea;
    case registry::view_presentation_role_t::shell_surface:
        return ads::LeftDockWidgetArea;
    case registry::view_presentation_role_t::tool_window: {
        const std::string& id = descriptor.id.value();
        if (id == "view.ai_chat")
            return ads::RightDockWidgetArea;
        if (descriptor.category == registry::view_category_t::explorer ||
            id == "view.navigator" || id == "view.analysis.functions" ||
            id == "view.programming.outline")
            return ads::LeftDockWidgetArea;
        return ads::CenterDockWidgetArea;
    }
    }
    return ads::CenterDockWidgetArea;
}

void AidaDockHost::place_new_dock(ads::CDockWidget* dock,
                                  const registry::qt_view_descriptor_t& descriptor) {
    manager_->addDockWidget(static_cast<ads::DockWidgetArea>(default_area_for(descriptor)), dock);
}

registry::view_operation_result_t AidaDockHost::host_open(
    const registry::qt_view_descriptor_t& descriptor,
    const registry::view_instance_id_t& id,
    const std::string& display_name) {
    if (descriptor.hub != registry::hub_kind_t::none) {
        ads::CDockWidget* hub = ensure_hub_dock(descriptor.hub);
        if (!hub)
            return {registry::view_operation_status_t::unavailable,
                "The hub dock could not be created"};
        hub->toggleView(true);
        hub->setAsCurrentTab();
        return {};
    }
    ads::CDockWidget* dock = ensure_dock(descriptor, id, display_name);
    if (!dock)
        return {registry::view_operation_status_t::unavailable,
            "The dock widget could not be created"};
    const auto found = docks_.find(dock->objectName().toStdString());
    if (found != docks_.end())
        ensure_content_for_open(dock, descriptor, id, found->second);
    dock->toggleView(true);
    dock->setAsCurrentTab();
    return {};
}

registry::view_operation_result_t AidaDockHost::host_focus(const registry::view_instance_id_t& id) {
    const auto* descriptor = registry_->find_descriptor(id.view);
    if (descriptor && descriptor->hub != registry::hub_kind_t::none) {
        ads::CDockWidget* hub = hub_dock(descriptor->hub);
        if (!hub)
            return {registry::view_operation_status_t::not_open, "The hub dock is not open"};
        hub->setAsCurrentTab();
        hub->raise();
        if (auto* widget = hub_widget(descriptor->hub))
            widget->setFocus(Qt::OtherFocusReason);
        return {};
    }
    ads::CDockWidget* dock = dock_for(id);
    if (!dock)
        return {registry::view_operation_status_t::not_open, "The dock widget is not open"};
    dock->setAsCurrentTab();
    dock->raise();
    if (QWidget* content = dock->widget())
        content->setFocus(Qt::OtherFocusReason);
    return {};
}

registry::view_operation_result_t AidaDockHost::host_close(const registry::view_instance_id_t& id) {
    const auto* descriptor = registry_->find_descriptor(id.view);
    if (descriptor && descriptor->hub != registry::hub_kind_t::none) {
        ads::CDockWidget* hub = hub_dock(descriptor->hub);
        if (!hub)
            return {};
        hub->closeDockWidget();
        return {};
    }
    ads::CDockWidget* dock = dock_for(id);
    if (!dock)
        return {};
    dock->closeDockWidget();
    return {};
}

registry::view_operation_result_t AidaDockHost::host_erase(const registry::view_instance_id_t& id) {
    ads::CDockWidget* dock = dock_for(id);
    if (!dock)
        return {};
    const std::string key = dock->objectName().toStdString();
    manager_->removeDockWidget(dock);
    docks_.erase(key);
    dock->deleteLater();
    mark_dirty("dock_erased");
    return {};
}

void AidaDockHost::host_deactivate(const registry::view_instance_id_t& id) {
    if (id.view.value() == "document.code") {
        if (code_group_hooks_.close_group) {
            code_group_hooks_.close_group(id);
        } else {
            diag::log_tagged_fmt("qt_dock_host",
                "code_group_close_skipped instance=%s reason=hook_not_installed",
                id.instance.c_str());
        }
        return;
    }
    if (id.view.value() == "document.hex") {
        if (hex_close_hook_)
            hex_close_hook_();
        else
            diag::log_tagged("qt_dock_host", "hex_close_skipped reason=hook_not_installed");
    }
}

void AidaDockHost::ensure_content_for_open(ads::CDockWidget* dock,
                                           const registry::qt_view_descriptor_t& descriptor,
                                           const registry::view_instance_id_t& id,
                                           dock_record_t& record) {
    if (record.content_pending) {
        static_cast<void>(realize_deferred_content(dock, record));
        return;
    }
    if (descriptor.content_policy != registry::content_policy_t::lazy_dispose)
        return;
    if (!record.content_disposed && dock->widget() != nullptr)
        return;
    QWidget* content = create_content(descriptor, id, dock);
    dock->setWidget(content, ads::CDockWidget::ForceNoScrollArea);
    record.content_disposed = false;
}

void AidaDockHost::dispose_content_for_close(ads::CDockWidget* dock, dock_record_t& record) {
    if (record.content_pending)
        return;
    const auto* descriptor = registry_->find_descriptor(record.instance.view);
    if (!descriptor || descriptor->content_policy != registry::content_policy_t::lazy_dispose)
        return;
    if (record.content_disposed || dock->widget() == nullptr)
        return;
    QWidget* content = dock->takeWidget();
    if (content)
        content->deleteLater();
    record.content_disposed = true;
}

void AidaDockHost::apply_pin(ads::CDockWidget* dock, bool pinned) {
    dock->setFeature(ads::CDockWidget::DockWidgetClosable, !pinned);
}

ads::CDockWidget* AidaDockHost::hub_dock(registry::hub_kind_t hub) const {
    const auto found = hub_docks_.find(hub);
    if (found == hub_docks_.end())
        return nullptr;
    return found->second.data();
}

AidaHubWidget* AidaDockHost::hub_widget(registry::hub_kind_t hub) const {
    const auto found = hub_widgets_.find(hub);
    if (found == hub_widgets_.end())
        return nullptr;
    return found->second.data();
}

ads::CDockWidget* AidaDockHost::ensure_hub_dock(registry::hub_kind_t hub, bool defer_pages) {
    if (ads::CDockWidget* existing = hub_dock(hub))
        return existing;
    const std::uint64_t started = ::GetTickCount64();
    auto* widget = new AidaHubWidget(hub, registry_, nullptr, defer_pages);
    const char* title = "Hub";
    switch (hub) {
    case registry::hub_kind_t::analysis: title = "Analysis"; break;
    case registry::hub_kind_t::scan: title = "Memory Scan"; break;
    case registry::hub_kind_t::types: title = "Types"; break;
    case registry::hub_kind_t::debugger: title = "Debugger"; break;
    case registry::hub_kind_t::network: title = "Network"; break;
    case registry::hub_kind_t::none: break;
    }
    auto* dock = new ads::CDockWidget(manager_, QLatin1String(title));
    dock->setObjectName(QString::fromStdString(registry::hub_object_name(hub)));
    dock->setFeatures(ads::CDockWidget::DockWidgetClosable |
        ads::CDockWidget::DockWidgetMovable |
        ads::CDockWidget::DockWidgetFloatable |
        ads::CDockWidget::DockWidgetFocusable |
        ads::CDockWidget::CustomCloseHandling);
    dock->setProperty("aida.hub", registry::hub_kind_name(hub));
    dock->setWidget(widget, ads::CDockWidget::ForceNoScrollArea);
    hub_widgets_[hub] = widget;
    hub_docks_[hub] = dock;
    wire_hub_dock(dock, hub);
    if (const auto* surface = surfaces_.find_hub(hub); surface && surface->pinned)
        apply_pin(dock, true);
    manager_->addDockWidget(ads::CenterDockWidgetArea, dock);
    diag::log_tagged_fmt("qt_dock_host",
        "hub_dock_created hub=%s defer_pages=%d elapsed_ms=%llu",
        registry::hub_kind_name(hub), defer_pages ? 1 : 0,
        static_cast<unsigned long long>(::GetTickCount64() - started));
    return dock;
}

void AidaDockHost::activate_hub_subview(registry::hub_kind_t hub, int subview) {
    ads::CDockWidget* dock = ensure_hub_dock(hub);
    if (!dock)
        return;
    if (auto* widget = hub_widget(hub))
        widget->set_subview(subview);
    registry_->note_hub_subview(hub, subview);
    surfaces_.set_hub_subview(hub, subview);
}

void AidaDockHost::handle_focused_dock_changed(ads::CDockWidget* now) {
    if (restoring_)
        return;
    if (!now) {
        registry_->update_focus(std::nullopt);
        return;
    }
    const std::string object_name = now->objectName().toStdString();
    for (const auto& entry : hub_docks_) {
        if (entry.second.data() == now) {
            if (const auto* widget = hub_widget(entry.first)) {
                const int subview = widget->current_subview();
                registry_->note_hub_subview(entry.first, subview);
                if (const auto active = registry_->hub_active_view(entry.first)) {
                    registry_->update_focus(registry::view_instance_id_t{*active,
                        registry::stable_view_instance_key_t{}});
                    Q_EMIT dockFocusGained(QString::fromStdString(active->value()));
                }
            }
            return;
        }
    }
    const auto found = docks_.find(object_name);
    if (found == docks_.end())
        return;
    registry_->update_focus(found->second.instance);
    Q_EMIT dockFocusGained(QString::fromStdString(found->second.instance.view.value()));
}

void AidaDockHost::reconcile_from_manager() {
    const QMap<QString, ads::CDockWidget*> docks = manager_->dockWidgetsMap();
    for (auto iterator = docks.begin(); iterator != docks.end(); ++iterator) {
        ads::CDockWidget* dock = iterator.value();
        const bool open = !dock->isClosed();
        const std::string object_name = dock->objectName().toStdString();
        const auto parsed = registry::parse_surface_identity(object_name);
        if (parsed.valid && parsed.hub != registry::hub_kind_t::none) {
            const registry::hub_kind_t hub = parsed.hub;
            registry_->for_each_descriptor(
                [&](const registry::qt_view_descriptor_t& descriptor) {
                    if (descriptor.hub != hub)
                        return;
                    registry_->sync_instance_visibility(
                        registry::view_instance_id_t{descriptor.id,
                            registry::stable_view_instance_key_t{}},
                        open, false);
                });
            continue;
        }
        if (!parsed.valid)
            continue;
        const registry::view_instance_id_t instance{parsed.view, parsed.instance};
        registry_->sync_instance_visibility(instance, open, false);
        if (open) {
            const auto found = docks_.find(object_name);
            if (found != docks_.end() && found->second.content_pending)
                static_cast<void>(realize_deferred_content(dock, found->second));
            continue;
        }
        const auto found = docks_.find(object_name);
        if (found != docks_.end() && !found->second.content_disposed)
            dispose_content_for_close(dock, found->second);
    }
    std::vector<registry::view_instance_id_t> focus_requests;
    registry_->for_each_instance(
        [&](const registry::qt_view_descriptor_t&,
            const registry::view_instance_state_t& instance) {
            if (instance.open && registry_->consume_focus_request(instance.id))
                focus_requests.push_back(instance.id);
        }, false);
    for (const auto& id : focus_requests)
        static_cast<void>(host_focus(id));
    handle_focused_dock_changed(manager_->focusedDockWidget());
}

void AidaDockHost::apply_hub_subview_selections() {
    for (const registry::hub_kind_t hub : {registry::hub_kind_t::analysis,
            registry::hub_kind_t::scan, registry::hub_kind_t::types,
            registry::hub_kind_t::debugger, registry::hub_kind_t::network}) {
        const auto stored = surfaces_.hub_subview(hub);
        if (!stored)
            continue;
        auto* widget = hub_widget(hub);
        if (!widget)
            continue;
        widget->set_subview(*stored);
        registry_->note_hub_subview(hub, *stored);
    }
}

void AidaDockHost::apply_surface_state() {
    for (auto& entry : docks_) {
        ads::CDockWidget* dock = manager_->findDockWidget(
            QString::fromStdString(entry.first));
        if (!dock)
            continue;
        const auto* surface = surfaces_.find(entry.second.instance);
        apply_pin(dock, surface && surface->pinned);
    }
    for (const auto& entry : hub_docks_) {
        ads::CDockWidget* dock = entry.second.data();
        if (!dock)
            continue;
        const auto* surface = surfaces_.find_hub(entry.first);
        apply_pin(dock, surface && surface->pinned);
    }
}

void AidaDockHost::replay_pending_surface_openings() {
    const bool workspace_available = disasm_view::capture_selected_workspace().operator bool();
    if (!workspace_available)
        return;
    std::vector<registry::surface_identity_parse_t> to_open;
    surfaces_.for_each([&](const std::string& identity,
                           const registry::surface_state_store_t::entry_t& entry) {
        const auto parsed = registry::parse_surface_identity(identity);
        if (!parsed.valid || parsed.hub != registry::hub_kind_t::none)
            return;
        if (!is_disassembly_side_instance({parsed.view, parsed.instance}))
            return;
        if (entry.restore_open)
            to_open.push_back(parsed);
    });
    for (const auto& parsed : to_open) {
        const registry::view_instance_id_t id{parsed.view, parsed.instance};
        if (!registry_->is_open(id))
            static_cast<void>(registry_->open(id, registry_->context(),
                "Disassembly: Side " + id.instance.value().substr(5)));
        if (auto* surface = surfaces_.find(id);
            surface && surface->restore_open && surface->presentation_pending &&
            disasm_view::restore_selected_presentation(id.instance.value(),
                surface->presentation))
            surface->presentation_pending = false;
    }
}

void AidaDockHost::update_start_center_auto_open() {
    const bool workspace_available = disasm_view::capture_selected_workspace().operator bool();
    const bool work = workspace_available ||
        (work_indicator_hook_ && work_indicator_hook_());
    if (!start_center_auto_open_ || !work)
        return;
    const auto* descriptor = registry_->find_descriptor(
        registry::stable_view_id_t("view.start_center"));
    if (descriptor) {
        const auto instance = registry_->instance_for(descriptor->id);
        if (registry_->is_open(instance))
            static_cast<void>(registry_->close(instance));
    }
    start_center_auto_open_ = false;
}

void AidaDockHost::notify_workspace_availability_changed() {
    update_start_center_auto_open();
    replay_pending_surface_openings();
    if (visibility_)
        visibility_->retry_deferred();
}

void AidaDockHost::dismiss_start_center_when_work_available() noexcept {
    try {
        start_center_auto_open_ = true;
    } catch (...) {
    }
}

registry::view_operation_result_t AidaDockHost::open_or_focus(
    const registry::stable_view_id_t& id) {
    const registry::stable_view_id_t target = registry_->canonical_view_id(id);
    if (target.value() == "view.start_center")
        start_center_auto_open_ = false;
    if (target.value() == "document.code") {
        const auto instance = active_code_instance();
        std::uint32_t group = 0;
        std::string label;
        if (parse_code_group_key(instance.instance, group) &&
            code_group_hooks_.label_for_group)
            label = code_group_hooks_.label_for_group(group);
        return registry_->open_or_focus(instance, registry_->context(), std::move(label));
    }
    return registry_->open_or_focus(registry_->instance_for(target), registry_->context());
}

registry::view_operation_result_t AidaDockHost::open_for_layout(
    const registry::stable_view_id_t& id) {
    const registry::stable_view_id_t target = registry_->canonical_view_id(id);
    if (target.value() == "document.code") {
        const auto instance = active_code_instance();
        std::uint32_t group = 0;
        std::string label;
        if (parse_code_group_key(instance.instance, group) &&
            code_group_hooks_.label_for_group)
            label = code_group_hooks_.label_for_group(group);
        return registry_->open(instance, registry_->context(), std::move(label));
    }
    return registry_->open(registry_->instance_for(target), registry_->context());
}

registry::view_operation_result_t AidaDockHost::close(const registry::stable_view_id_t& id) {
    const registry::stable_view_id_t target = registry_->canonical_view_id(id);
    if (target.value() == "view.start_center")
        start_center_auto_open_ = false;
    if (target.value() == "document.code")
        return close_instance(active_code_instance());
    return close_instance(registry_->instance_for(target));
}

registry::view_operation_result_t AidaDockHost::close_instance(
    const registry::view_instance_id_t& id) {
    const auto* descriptor = registry_->find_descriptor(id.view);
    if (!descriptor)
        return {registry::view_operation_status_t::not_registered,
            "The target view is not registered"};
    const registry::surface_state_store_t::entry_t* surface = nullptr;
    if (descriptor->hub != registry::hub_kind_t::none)
        surface = surfaces_.find_hub(descriptor->hub);
    else
        surface = surfaces_.find(id);
    if (surface && surface->pinned)
        return {registry::view_operation_status_t::unavailable,
            "Unpin this view before closing it"};
    if (id.view.value() == "document.code" && code_group_hooks_.prepare_close) {
        const auto prepared = code_group_hooks_.prepare_close(id);
        if (!prepared.ok())
            return prepared;
    }
    const auto result = registry_->close(id);
    if (result.ok() && id.view.value() == "document.disassembly" && !id.instance.empty()) {
        disasm_view::release_presentation(id.instance.value());
        auto& surface_entry = surfaces_.ensure(id);
        surface_entry.restore_open = false;
        surface_entry.presentation_pending = false;
        mark_dirty("disasm_side_closed");
    }
    return result;
}

registry::view_operation_result_t AidaDockHost::close_other_instances(
    const registry::view_instance_id_t& keep) {
    std::vector<registry::view_instance_id_t> targets;
    registry_->for_each_instance([&](const registry::qt_view_descriptor_t& descriptor,
            const registry::view_instance_state_t& instance) {
        if (!(instance.id == keep) && instance.open && descriptor.closeable &&
            descriptor.hub == registry::hub_kind_t::none) {
            const auto* surface = surfaces_.find(instance.id);
            if (!surface || !surface->pinned)
                targets.push_back(instance.id);
        }
    }, true);
    if (targets.empty())
        return {registry::view_operation_status_t::unavailable,
            "No other closeable unpinned view is open"};
    for (const auto& target : targets) {
        if (target.view.value() != "document.code" || !code_group_hooks_.prepare_close)
            continue;
        const auto prepared = code_group_hooks_.prepare_close(target);
        if (!prepared.ok())
            return prepared;
    }
    for (const auto& target : targets) {
        const auto result = close_instance(target);
        if (!result.ok())
            return result;
    }
    return {registry::view_operation_status_t::completed, {}};
}

registry::view_operation_result_t AidaDockHost::toggle_pin(
    const registry::view_instance_id_t& id) {
    if (!registry_->is_open(id))
        return {registry::view_operation_status_t::not_open,
            "The target view is no longer open"};
    const auto* descriptor = registry_->find_descriptor(id.view);
    const bool hub_member = descriptor && descriptor->hub != registry::hub_kind_t::none;
    auto& entry = hub_member
        ? surfaces_.ensure_hub(descriptor->hub)
        : surfaces_.ensure(id);
    entry.pinned = !entry.pinned;
    ads::CDockWidget* dock = hub_member ? hub_dock(descriptor->hub) : dock_for(id);
    if (dock)
        apply_pin(dock, entry.pinned);
    surfaces_.note_changed();
    mark_dirty("pin_toggled");
    return {registry::view_operation_status_t::completed,
        entry.pinned ? "View pinned" : "View unpinned"};
}

registry::view_operation_result_t AidaDockHost::request_reset_state(
    const registry::view_instance_id_t& id) {
    if (!registry_->is_open(id))
        return {registry::view_operation_status_t::not_open,
            "The target view is no longer open"};
    if (id.view.value() == "document.disassembly" && !id.instance.empty())
        disasm_view::reset_presentation(id.instance.value());
    const auto* descriptor = registry_->find_descriptor(id.view);
    if (!descriptor)
        return {registry::view_operation_status_t::not_registered,
            "The target view is not registered"};
    if (descriptor->hub == registry::hub_kind_t::none) {
        if (ads::CDockWidget* dock = dock_for(id)) {
            const auto found = docks_.find(dock->objectName().toStdString());
            if (found != docks_.end() && found->second.content_pending) {
                static_cast<void>(realize_deferred_content(dock, found->second));
            } else if (QWidget* content = dock->takeWidget()) {
                QWidget* replacement = create_content(*descriptor, id, dock);
                dock->setWidget(replacement, ads::CDockWidget::ForceNoScrollArea);
                content->deleteLater();
            }
        }
    } else if (auto* hub = hub_widget(descriptor->hub)) {
        hub->rebuild_page(descriptor->hub_subview);
    }
    return {registry::view_operation_status_t::completed, {}};
}

registry::view_operation_result_t AidaDockHost::duplicate_instance(
    const registry::view_instance_id_t& id) {
    if (id.view.value() != "document.disassembly")
        return {registry::view_operation_status_t::unavailable,
            "This renderer does not declare independent duplicate state"};
    if (!registry_->is_open(id))
        return {registry::view_operation_status_t::not_open,
            "The source Disassembly view is no longer open"};
    if (!disasm_view::capture_selected_workspace())
        return {registry::view_operation_status_t::unavailable,
            "Open and analyze a binary before creating a Disassembly side view"};
    if (persistence_ && persistence_->operation_pending())
        return {registry::view_operation_status_t::unavailable,
            "A workspace layout transaction is in progress"};
    if (layout_locked_)
        return {registry::view_operation_status_t::unavailable,
            "Unlock the workspace layout before opening Disassembly to the side"};
    constexpr unsigned maximum_side_instances = 3;
    for (unsigned index = 1; index <= maximum_side_instances; ++index) {
        const std::string key = "side." + std::to_string(index);
        const registry::view_instance_id_t target{id.view,
            registry::stable_view_instance_key_t(key)};
        if (registry_->is_open(target))
            continue;
        disasm_view::clone_presentation(id.instance.value(), key);
        const auto result = registry_->open(target, registry_->context(),
            "Disassembly: Side " + std::to_string(index));
        if (!result.ok()) {
            disasm_view::release_presentation(key);
            return result;
        }
        ads::CDockWidget* side_dock = dock_for(target);
        ads::CDockWidget* source_dock = dock_for(id);
        ads::CDockAreaWidget* source_area = source_dock
            ? source_dock->dockAreaWidget() : nullptr;
        if (!side_dock || !source_area) {
            static_cast<void>(registry_->close(target));
            disasm_view::release_presentation(key);
            return {registry::view_operation_status_t::unavailable,
                "The source Disassembly dock could not be split; realize the document and unlock the layout before retrying"};
        }
        ads::CDockAreaWidget* split_area = manager_->addDockWidget(
            ads::RightDockWidgetArea, side_dock, source_area);
        if (split_area) {
            const int width = (std::max)(source_area->width(), 2);
            manager_->setSplitterSizes(source_area, {width / 2, width / 2});
        }
        surfaces_.ensure(target).restore_open = true;
        surfaces_.note_changed();
        mark_dirty("disasm_side_opened");
        return {registry::view_operation_status_t::completed,
            "Opened independent Disassembly side view " + std::to_string(index)};
    }
    return {registry::view_operation_status_t::unavailable,
        "The bounded limit of three Disassembly side views is already open"};
}

registry::view_operation_result_t AidaDockHost::reopen_last_closed() {
    return registry_->reopen_last_closed(registry_->context());
}

registry::view_operation_result_t AidaDockHost::open_default_missing() {
    return registry_->open_default_missing(registry_->context());
}

bool AidaDockHost::is_open(const registry::stable_view_id_t& id) noexcept {
    try {
        const registry::stable_view_id_t target = registry_->canonical_view_id(id);
        if (target.value() == "document.code")
            return registry_->is_open(active_code_instance());
        return registry_->is_open(registry_->instance_for(target));
    } catch (...) {
        return false;
    }
}

bool AidaDockHost::is_pinned(const registry::view_instance_id_t& id) noexcept {
    try {
        const auto* descriptor = registry_->find_descriptor(id.view);
        if (descriptor && descriptor->hub != registry::hub_kind_t::none) {
            const auto* surface = surfaces_.find_hub(descriptor->hub);
            return surface && surface->pinned;
        }
        const auto* surface = surfaces_.find(id);
        return surface && surface->pinned;
    } catch (...) {
        return false;
    }
}

bool AidaDockHost::can_duplicate(const registry::view_instance_id_t& id) noexcept {
    try {
        if (id.view.value() != "document.disassembly" ||
            !registry_->is_open(id) || !disasm_view::capture_selected_workspace() ||
            layout_locked_ || (persistence_ && persistence_->operation_pending()))
            return false;
        unsigned open_side_instances = 0;
        registry_->for_each_instance(
            [&](const registry::qt_view_descriptor_t&, const registry::view_instance_state_t& instance) {
                if (instance.open && instance.id.view == id.view &&
                    !instance.id.instance.empty())
                    ++open_side_instances;
            }, true);
        return open_side_instances < 3;
    } catch (...) {
        return false;
    }
}

bool AidaDockHost::can_reset_state(const registry::view_instance_id_t& id) noexcept {
    try {
        return registry_->is_open(id);
    } catch (...) {
        return false;
    }
}

bool AidaDockHost::can_reopen_last_closed() noexcept {
    try {
        return registry_->can_reopen_last_closed();
    } catch (...) {
        return false;
    }
}

std::string AidaDockHost::focused_disassembly_presentation_key() noexcept {
    try {
        const auto focused = registry_->focused_instance();
        if (focused && focused->view.value() == "document.disassembly")
            return focused->instance.value();
    } catch (...) {
    }
    return {};
}

void AidaDockHost::for_each_menu_entry(
    const std::function<void(const registry::menu_entry_t&)>& visitor) {
    registry_->for_each_menu_entry(visitor);
}

registry::view_operation_result_t AidaDockHost::float_instance(
    const registry::view_instance_id_t& id) {
    if (persistence_ && persistence_->operation_pending())
        return {registry::view_operation_status_t::unavailable,
            "A workspace layout transaction is in progress"};
    if (layout_locked_)
        return {registry::view_operation_status_t::unavailable,
            "Unlock the workspace layout before floating this view"};
    const auto* descriptor = registry_->find_descriptor(id.view);
    ads::CDockWidget* dock = descriptor && descriptor->hub != registry::hub_kind_t::none
        ? hub_dock(descriptor->hub) : dock_for(id);
    if (!dock || dock->isClosed())
        return {registry::view_operation_status_t::not_open, "The target view is not open"};
    if (dock->isFloating())
        return {registry::view_operation_status_t::completed, "View is already floating"};
    dock->setFloating();
    mark_dirty("dock_floated");
    return {registry::view_operation_status_t::completed, {}};
}

registry::view_operation_result_t AidaDockHost::move_instance(
    const registry::view_instance_id_t& id, dock_region_t region) {
    if (persistence_ && persistence_->operation_pending())
        return {registry::view_operation_status_t::unavailable,
            "A workspace layout transaction is in progress"};
    if (layout_locked_)
        return {registry::view_operation_status_t::unavailable,
            "Unlock the workspace layout before moving this view"};
    const auto* descriptor = registry_->find_descriptor(id.view);
    ads::CDockWidget* dock = descriptor && descriptor->hub != registry::hub_kind_t::none
        ? hub_dock(descriptor->hub) : dock_for(id);
    if (!dock || dock->isClosed())
        return {registry::view_operation_status_t::not_open, "The target view is not open"};
    ads::DockWidgetArea area = ads::CenterDockWidgetArea;
    switch (region) {
    case dock_region_t::left: area = ads::LeftDockWidgetArea; break;
    case dock_region_t::right: area = ads::RightDockWidgetArea; break;
    case dock_region_t::bottom: area = ads::BottomDockWidgetArea; break;
    case dock_region_t::center: area = ads::CenterDockWidgetArea; break;
    }
    manager_->addDockWidget(area, dock, nullptr);
    mark_dirty("dock_moved");
    return {registry::view_operation_status_t::completed, {}};
}

void AidaDockHost::set_code_group_hooks(code_group_hooks_t hooks) {
    code_group_hooks_ = std::move(hooks);
}

registry::view_instance_id_t AidaDockHost::active_code_instance() {
    std::uint32_t group = 0;
    if (code_group_hooks_.active_group)
        group = code_group_hooks_.active_group();
    return {registry::stable_view_id_t("document.code"),
        registry::stable_view_instance_key_t("group." + std::to_string(group))};
}

void AidaDockHost::synchronize_code_groups() {
    if (!code_group_hooks_.current_groups)
        return;
    const std::set<std::uint32_t> groups = code_group_hooks_.current_groups();
    for (const std::uint32_t group : groups) {
        const registry::view_instance_id_t instance{
            registry::stable_view_id_t("document.code"),
            registry::stable_view_instance_key_t("group." + std::to_string(group))};
        std::string label;
        if (code_group_hooks_.label_for_group)
            label = code_group_hooks_.label_for_group(group);
        if (registry_->is_open(instance))
            static_cast<void>(registry_->open(instance, registry_->context(),
                std::move(label)));
    }

    std::vector<registry::view_instance_id_t> retired;
    registry_->for_each_instance(
        [&](const registry::qt_view_descriptor_t&,
            const registry::view_instance_state_t& instance) {
            if (instance.id.view != registry::stable_view_id_t("document.code"))
                return;
            std::uint32_t group = 0;
            if (!parse_code_group_key(instance.id.instance, group) ||
                groups.find(group) == groups.end())
                retired.push_back(instance.id);
        });
    for (const auto& instance : retired) {
        if (registry_->is_open(instance))
            static_cast<void>(registry_->close(instance));
        static_cast<void>(registry_->erase_closed_instance(instance));
    }
}

void AidaDockHost::set_hex_close_hook(std::function<void()> hook) {
    hex_close_hook_ = std::move(hook);
}

void AidaDockHost::set_work_indicator_hook(std::function<bool()> hook) {
    work_indicator_hook_ = std::move(hook);
}

void AidaDockHost::set_layout_locked(bool locked) {
    if (layout_locked_ == locked) {
        manager_->lockDockWidgetFeaturesGlobally(locked
            ? (ads::CDockWidget::DockWidgetMovable | ads::CDockWidget::DockWidgetFloatable)
            : ads::CDockWidget::NoDockWidgetFeatures);
        refresh_splitter_locks();
        return;
    }
    layout_locked_ = locked;
    manager_->lockDockWidgetFeaturesGlobally(locked
        ? (ads::CDockWidget::DockWidgetMovable | ads::CDockWidget::DockWidgetFloatable)
        : ads::CDockWidget::NoDockWidgetFeatures);
    refresh_splitter_locks();
    mark_dirty("layout_lock_changed");
}

void AidaDockHost::wire_layout_watchers() {
    const auto prune = [](std::vector<QPointer<QObject>>& watched) {
        watched.erase(std::remove_if(watched.begin(), watched.end(),
            [](const QPointer<QObject>& known) { return known.isNull(); }),
            watched.end());
    };
    prune(watched_splitters_);
    prune(watched_areas_);
    const auto already_watched = [](const std::vector<QPointer<QObject>>& watched,
                                    QObject* candidate) {
        return std::any_of(watched.begin(), watched.end(),
            [candidate](const QPointer<QObject>& known) { return known == candidate; });
    };
    for (ads::CDockContainerWidget* container : manager_->dockContainers()) {
        if (!container)
            continue;
        const QList<ads::CDockSplitter*> splitters =
            container->findChildren<ads::CDockSplitter*>();
        for (ads::CDockSplitter* splitter : splitters) {
            if (!splitter || already_watched(watched_splitters_, splitter))
                continue;
            watched_splitters_.push_back(splitter);
            connect(splitter, &QSplitter::splitterMoved, this,
                    [this](int, int) { mark_dirty("splitter_moved"); });
        }
        const int area_count = container->dockAreaCount();
        for (int index = 0; index < area_count; ++index) {
            ads::CDockAreaWidget* area = container->dockArea(index);
            if (!area || already_watched(watched_areas_, area))
                continue;
            watched_areas_.push_back(area);
            connect(area, &ads::CDockAreaWidget::currentChanged, this,
                    [this](int) { mark_dirty("area_tab_changed"); });
        }
    }
}

void AidaDockHost::refresh_splitter_locks() {
    if (!splitter_lock_filter_)
        return;
    const auto install = [this](QWidget* container) {
        if (!container)
            return;
        const QList<QSplitter*> splitters = container->findChildren<QSplitter*>();
        for (QSplitter* splitter : splitters) {
            for (int index = 0; index < splitter->count(); ++index) {
                if (QSplitterHandle* handle = splitter->handle(index))
                    handle->installEventFilter(splitter_lock_filter_);
            }
        }
    };
    install(manager_);
    const QList<ads::CFloatingDockContainer*> floating = manager_->floatingWidgets();
    for (ads::CFloatingDockContainer* container : floating)
        install(container);
}

void AidaDockHost::realize_open_instances() {
    std::vector<registry::view_instance_id_t> open_instances;
    registry_->for_each_instance(
        [&](const registry::qt_view_descriptor_t&,
            const registry::view_instance_state_t& instance) {
            if (instance.open)
                open_instances.push_back(instance.id);
        }, false);
    for (const auto& id : open_instances) {
        const auto* descriptor = registry_->find_descriptor(id.view);
        if (!descriptor)
            continue;
        if (descriptor->hub != registry::hub_kind_t::none) {
            if (ads::CDockWidget* hub = ensure_hub_dock(descriptor->hub))
                hub->toggleView(true);
            continue;
        }
        if (ads::CDockWidget* existing = dock_for(id)) {
            const auto found = docks_.find(existing->objectName().toStdString());
            if (found != docks_.end() && found->second.content_pending)
                static_cast<void>(realize_deferred_content(existing, found->second));
            continue;
        }
        ads::CDockWidget* dock = create_dock(*descriptor, id, {});
        place_new_dock(dock, *descriptor);
        dock->toggleView(true);
    }
}

void AidaDockHost::preregister_all_docks() {
    restoring_ = true;
    manager_->setUpdatesEnabled(false);
    const std::uint64_t started = ::GetTickCount64();
    std::size_t deferred = 0;
    std::size_t realized = 0;
    registry_->for_each_descriptor([&](const registry::qt_view_descriptor_t& descriptor) {
        if (descriptor.hub != registry::hub_kind_t::none)
            return;
        std::vector<registry::view_instance_id_t> instances;
        if (descriptor.identity_policy == registry::view_identity_policy_t::singleton) {
            instances.push_back(registry_->instance_for(descriptor.id));
        } else if (descriptor.id.value() == "document.code") {
            if (code_group_hooks_.current_groups) {
                for (const std::uint32_t group : code_group_hooks_.current_groups())
                    instances.push_back({descriptor.id,
                        registry::stable_view_instance_key_t(
                            "group." + std::to_string(group))});
            }
        } else {
            instances.push_back({descriptor.id, registry::stable_view_instance_key_t("primary")});
            if (descriptor.id.value() == "document.disassembly") {
                for (unsigned side = 1; side <= 3; ++side) {
                    const registry::view_instance_id_t side_id{descriptor.id,
                        registry::stable_view_instance_key_t(
                            "side." + std::to_string(side))};
                    if (const auto* surface = surfaces_.find(side_id);
                        surface && surface->restore_open)
                        instances.push_back(side_id);
                }
            }
        }
        for (const auto& instance : instances) {
            if (dock_for(instance))
                continue;
            std::string display;
            if (descriptor.id.value() == "document.code") {
                std::uint32_t group = 0;
                if (parse_code_group_key(instance.instance, group) &&
                    code_group_hooks_.label_for_group)
                    display = code_group_hooks_.label_for_group(group);
            } else if (is_disassembly_side_instance(instance)) {
                display = "Disassembly: Side " + instance.instance.value().substr(5);
            }
            const bool open = registry_->is_open(instance);
            ads::CDockWidget* dock = create_dock(descriptor, instance, display,
                !open);
            if (open)
                ++realized;
            else
                ++deferred;
            place_new_dock(dock, descriptor);
            if (!open)
                dock->toggleView(false);
        }
    });
    for (const registry::hub_kind_t hub : {registry::hub_kind_t::analysis,
            registry::hub_kind_t::scan, registry::hub_kind_t::types,
            registry::hub_kind_t::debugger, registry::hub_kind_t::network}) {
        ads::CDockWidget* dock = ensure_hub_dock(hub, true);
        if (dock)
            dock->toggleView(false);
    }
    realize_open_instances();
    manager_->setUpdatesEnabled(true);
    restoring_ = false;
    diag::log_tagged_fmt("qt_dock_host",
        "preregister_complete docks=%zu deferred=%zu realized=%zu elapsed_ms=%llu",
        docks_.size(), deferred, realized,
        static_cast<unsigned long long>(::GetTickCount64() - started));
}

bool AidaDockHost::apply_state(const std::string& dock_xml) {
    if (dock_xml.empty())
        return false;
    const QByteArray payload(dock_xml.data(), static_cast<qsizetype>(dock_xml.size()));
    const std::uint64_t started = ::GetTickCount64();
    manager_->setUpdatesEnabled(false);
    const bool ok = manager_->restoreState(payload, 4);
    manager_->setUpdatesEnabled(true);
    diag::log_tagged_fmt("qt_dock_host",
        "layout_apply_state ok=%d payload_bytes=%llu elapsed_ms=%llu",
        ok ? 1 : 0,
        static_cast<unsigned long long>(dock_xml.size()),
        static_cast<unsigned long long>(::GetTickCount64() - started));
    return ok;
}

QByteArray AidaDockHost::capture_state() {
    return manager_->saveState(4);
}

std::string AidaDockHost::capture_surface_json() {
    std::vector<registry::view_instance_id_t> side_ids;
    surfaces_.for_each([&](const std::string& identity,
                           const registry::surface_state_store_t::entry_t&) {
        const auto parsed = registry::parse_surface_identity(identity);
        if (parsed.valid && parsed.hub == registry::hub_kind_t::none &&
            parsed.view.value() == "document.disassembly" && !parsed.instance.empty())
            side_ids.push_back({parsed.view, parsed.instance});
    });
    registry_->for_each_instance(
        [&](const registry::qt_view_descriptor_t&,
            const registry::view_instance_state_t& instance) {
            if (instance.open && instance.id.view.value() == "document.disassembly" &&
                !instance.id.instance.empty())
                side_ids.push_back(instance.id);
        });
    std::sort(side_ids.begin(), side_ids.end());
    side_ids.erase(std::unique(side_ids.begin(), side_ids.end()), side_ids.end());
    for (const auto& id : side_ids) {
        auto& entry = surfaces_.ensure(id);
        entry.restore_open = registry_->is_open(id);
        if (entry.restore_open) {
            disasm_view::presentation_snapshot_t snapshot;
            if (disasm_view::capture_selected_presentation(id.instance.value(), snapshot)) {
                entry.presentation = snapshot;
                entry.presentation_pending = true;
            }
        }
    }
    surfaces_.note_changed();
    return registry::capture_surface_state_json(surfaces_);
}

bool AidaDockHost::load_surface_json(const std::string& json_text) {
    return registry::load_surface_state_json(json_text, surfaces_,
        [this](const registry::stable_view_id_t& id) {
            return registry_->find_descriptor(registry_->canonical_view_id(id)) != nullptr;
        });
}

bool AidaDockHost::restoreOrBuildDefault() {
    const bool result = persistence_ && persistence_->restore_or_build_default();
    wire_layout_watchers();
    update_empty_state();
    return result;
}

void AidaDockHost::persistNow() {
    if (persistence_)
        persistence_->shutdown();
}

workspace_request_result_t AidaDockHost::open_missing_views() {
    if (persistence_)
        return persistence_->open_missing_views();
    return workspace_request_result_t::unavailable;
}

void AidaDockHost::build_preset_layout(workspace_preset_t preset, bool missing_only) {
    const QByteArray before = capture_state();
    try {
        manager_->setUpdatesEnabled(false);
        restoring_ = true;

        registry_->for_each_descriptor([&](const registry::qt_view_descriptor_t& descriptor) {
            if (!preset_default_opens_view(preset, descriptor.id.value()))
                return;
            static_cast<void>(open_for_layout(descriptor.id));
        });
        realize_open_instances();

        const preset_recipe_t& recipe = preset_recipe(preset);
        const int logical_width = (std::max)(manager_->width(), 1);
        const int logical_height = (std::max)(manager_->height(), 1);

        const auto dock_for_id = [this](const char* stable_id) -> ads::CDockWidget* {
            const registry::stable_view_id_t id(stable_id);
            const registry::stable_view_id_t canonical = registry_->canonical_view_id(id);
            const auto* descriptor = registry_->find_descriptor(canonical);
            if (descriptor && descriptor->hub != registry::hub_kind_t::none)
                return hub_dock(descriptor->hub);
            return dock_for(registry_->instance_for(canonical));
        };
        const auto select_recipe_tab = [this](const char* stable_id) {
            const registry::stable_view_id_t canonical = registry_->canonical_view_id(
                registry::stable_view_id_t(stable_id));
            const auto* descriptor = registry_->find_descriptor(canonical);
            if (descriptor && descriptor->hub != registry::hub_kind_t::none)
                activate_hub_subview(descriptor->hub, descriptor->hub_subview);
        };
        const auto is_open_id = [this](const char* stable_id) {
            return is_open(registry::stable_view_id_t(stable_id));
        };

        if (compact_single_node_recipe(static_cast<float>(logical_width),
                static_cast<float>(logical_height))) {
            ads::CDockAreaWidget* anchor = nullptr;
            const auto dock_compact = [&](const std::vector<const char*>& ids) {
                for (const char* stable_id : ids) {
                    if (missing_only && !is_open_id(stable_id))
                        static_cast<void>(open_for_layout(registry::stable_view_id_t(stable_id)));
                    ads::CDockWidget* dock = dock_for_id(stable_id);
                    if (!dock || dock->isClosed())
                        continue;
                    if (missing_only && dock->dockAreaWidget() != nullptr)
                        continue;
                    if (!anchor)
                        anchor = manager_->addDockWidget(ads::CenterDockWidgetArea, dock);
                    else
                        manager_->addDockWidgetTabToArea(dock, anchor);
                }
            };
            dock_compact(recipe.left);
            dock_compact(recipe.center);
            dock_compact(recipe.right);
            dock_compact(recipe.bottom);
            const char* primary = is_open_id("view.start_center")
                ? "view.start_center" : compact_primary_view(preset);
            select_recipe_tab(primary);
            if (ads::CDockWidget* selected = dock_for_id(primary)) {
                if (anchor)
                    anchor->setCurrentDockWidget(selected);
                selected->setAsCurrentTab();
            }
        } else {
            ads::CDockAreaWidget* anchors[4] = {nullptr, nullptr, nullptr, nullptr};
            const ads::DockWidgetArea areas[4] = {ads::LeftDockWidgetArea,
                ads::CenterDockWidgetArea, ads::RightDockWidgetArea, ads::BottomDockWidgetArea};
            const std::vector<const char*>* stacks[4] = {&recipe.left, &recipe.center,
                &recipe.right, &recipe.bottom};
            for (int stack = 0; stack < 4; ++stack) {
                for (const char* stable_id : *stacks[stack]) {
                    if (missing_only && !is_open_id(stable_id))
                        static_cast<void>(open_for_layout(registry::stable_view_id_t(stable_id)));
                    ads::CDockWidget* dock = dock_for_id(stable_id);
                    if (!dock || dock->isClosed())
                        continue;
                    if (missing_only && dock->dockAreaWidget() != nullptr)
                        continue;
                    if (!anchors[stack])
                        anchors[stack] = manager_->addDockWidget(areas[stack], dock);
                    else
                        manager_->addDockWidgetTabToArea(dock, anchors[stack]);
                }
            }
            registry_->for_each_instance(
                [&](const registry::qt_view_descriptor_t& descriptor,
                    const registry::view_instance_state_t& instance) {
                    if (!instance.open || descriptor.hub != registry::hub_kind_t::none)
                        return;
                    ads::CDockWidget* dock = dock_for(instance.id);
                    if (!dock || dock->isClosed() || dock->isFloating())
                        return;
                    bool in_recipe = false;
                    for (int stack = 0; stack < 4 && !in_recipe; ++stack)
                        for (const char* stable_id : *stacks[stack])
                            if (descriptor.id.value() == stable_id) {
                                in_recipe = true;
                                break;
                            }
                    if (in_recipe)
                        return;
                    const int area_index = [&] {
                        switch (descriptor.role) {
                        case registry::view_presentation_role_t::document: return 1;
                        case registry::view_presentation_role_t::inspector: return 2;
                        case registry::view_presentation_role_t::bottom_panel: return 3;
                        case registry::view_presentation_role_t::shell_surface: return 0;
                        case registry::view_presentation_role_t::tool_window: return 0;
                        }
                        return 1;
                    }();
                    if (anchors[area_index])
                        manager_->addDockWidgetTabToArea(dock, anchors[area_index]);
                    else
                        anchors[area_index] = manager_->addDockWidget(areas[area_index], dock);
                });

            const layout_ratios_t ratios = calculate_layout_ratios(preset,
                static_cast<float>(logical_width), static_cast<float>(logical_height),
                [this](std::initializer_list<const char*> ids) {
                    float width = 0.0f;
                    for (const char* stable_id : ids) {
                        const auto* descriptor = registry_->find_descriptor(
                            registry_->canonical_view_id(registry::stable_view_id_t(stable_id)));
                        if (descriptor)
                            width = (std::max)(width, descriptor->minimum_size.width);
                    }
                    return width;
                });
            const auto apply_to_area = [](ads::CDockAreaWidget* area, int target_px) {
                if (!area)
                    return;
                auto* splitter = area->parentSplitter();
                if (!splitter || splitter->count() < 2)
                    return;
                QList<int> sizes = splitter->sizes();
                const int index = splitter->indexOf(area);
                if (index < 0 || index >= sizes.size())
                    return;
                sizes[index] = target_px;
                splitter->setSizes(sizes);
            };
            ads::CDockAreaWidget* anchor_left = anchors[0];
            ads::CDockAreaWidget* anchor_right = anchors[2];
            ads::CDockAreaWidget* anchor_bottom = anchors[3];
            auto apply_ratios = [apply_to_area, anchor_left, anchor_right, anchor_bottom,
                    ratios, logical_width, logical_height] {
                apply_to_area(anchor_bottom,
                    static_cast<int>(logical_height * ratios.bottom));
                apply_to_area(anchor_left,
                    static_cast<int>(logical_width * ratios.left));
                apply_to_area(anchor_right,
                    static_cast<int>(logical_width * ratios.right));
            };
            apply_ratios();

            const char* selections[4] = {recipe.select_left, recipe.select_center,
                recipe.select_right, recipe.select_bottom};
            for (int stack = 0; stack < 4; ++stack) {
                if (!anchors[stack] || !selections[stack])
                    continue;
                select_recipe_tab(selections[stack]);
                if (ads::CDockWidget* selected = dock_for_id(selections[stack]))
                    anchors[stack]->setCurrentDockWidget(selected);
            }
            if (is_open_id("view.start_center")) {
                if (ads::CDockWidget* start = dock_for_id("view.start_center")) {
                    if (anchors[1])
                        anchors[1]->setCurrentDockWidget(start);
                    start->setAsCurrentTab();
                }
            }
            QTimer::singleShot(0, this, [this, apply_ratios] {
                apply_ratios();
                QTimer::singleShot(0, this, [this] {
                    refresh_splitter_locks();
                    mark_dirty("preset_realized");
                });
            });
        }
        restoring_ = false;
        manager_->setUpdatesEnabled(true);
        refresh_splitter_locks();
        wire_layout_watchers();
        mark_dirty("preset_built");
    } catch (...) {
        restoring_ = false;
        manager_->setUpdatesEnabled(true);
        diag::log_tagged_critical("qt_dock_host",
            "preset_build_exception rollback=before_switch_snapshot");
        if (!before.isEmpty())
            static_cast<void>(manager_->restoreState(before, 4));
    }
}

}
