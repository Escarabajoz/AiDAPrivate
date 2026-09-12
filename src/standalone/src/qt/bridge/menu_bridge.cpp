#include "qt/bridge/menu_bridge.hpp"

#include <QAction>
#include <QApplication>
#include <QElapsedTimer>
#include <QMenu>
#include <QMenuBar>

#include <algorithm>
#include <cstring>
#include <utility>

#include "helpers/diag_log.hpp"
#include "qt/bridge/action_bridge.hpp"
#include "qt/chrome/chrome_visibility_tracer.hpp"
#include "qt/bridge/interaction_context_provider.hpp"
#include "qt/docking/dock_host.hpp"
#include "qt/docking/preset_recipes.hpp"
#include "qt/layout/workspace_persistence.hpp"
#include "qt/theme/aida_icons.hpp"

namespace aida::qt::bridge {

namespace {

void clear_menu(QMenu* menu) {
    if (!menu)
        return;
    menu->clear();
    const auto child_actions = menu->findChildren<QAction*>(QString(), Qt::FindDirectChildrenOnly);
    for (QAction* child : child_actions) {
        if (!child)
            continue;
        child->setParent(nullptr);
        child->deleteLater();
    }
    const auto child_menus = menu->findChildren<QMenu*>(QString(), Qt::FindDirectChildrenOnly);
    for (QMenu* child : child_menus) {
        if (!child)
            continue;
        child->setParent(nullptr);
        child->deleteLater();
    }
}

QAction* add_text_row(QMenu* menu, const QString& text, const QString& name) {
    if (!menu)
        return nullptr;
    QAction* row = new QAction(text, menu);
    row->setObjectName(name);
    row->setEnabled(false);
    menu->addAction(row);
    return row;
}

struct top_menu_rule_t {
    const char* prefix;
    MenuBridge::top_menu_t menu;
};

constexpr top_menu_rule_t k_top_menu_rules[] = {
    {"file.", MenuBridge::top_menu_t::file},
    {"edit.", MenuBridge::top_menu_t::edit},
    {"editor.ai.", MenuBridge::top_menu_t::ai},
    {"navigate.", MenuBridge::top_menu_t::navigate},
    {"analysis.", MenuBridge::top_menu_t::analysis},
    {"debugger.", MenuBridge::top_menu_t::debugger_},
    {"debug.", MenuBridge::top_menu_t::debugger_},
    {"memory.", MenuBridge::top_menu_t::memory},
    {"network.", MenuBridge::top_menu_t::network},
    {"tools.", MenuBridge::top_menu_t::tools},
    {"ai.", MenuBridge::top_menu_t::ai},
    {"help.", MenuBridge::top_menu_t::help},
};

std::optional<MenuBridge::top_menu_t> top_menu_for_action_id(const std::string& id) {
    std::optional<MenuBridge::top_menu_t> best;
    std::size_t best_length = 0;
    for (const auto& rule : k_top_menu_rules) {
        const std::size_t length = std::strlen(rule.prefix);
        if (length > best_length && id.compare(0, length, rule.prefix) == 0) {
            best = rule.menu;
            best_length = length;
        }
    }
    return best;
}

const char* top_menu_plain_title(MenuBridge::top_menu_t which) noexcept {
    using top = MenuBridge::top_menu_t;
    switch (which) {
    case top::file: return "File";
    case top::edit: return "Edit";
    case top::view: return "View";
    case top::navigate: return "Navigate";
    case top::analysis: return "Analysis";
    case top::debugger_: return "Debugger";
    case top::memory: return "Memory";
    case top::types: return "Types";
    case top::network: return "Network";
    case top::workspace: return "Workspace";
    case top::tools: return "Tools";
    case top::ai: return "AI";
    case top::help: return "Help";
    }
    return "";
}

QString registry_group_header(const std::string& display_name, const char* menu_title) {
    std::string name = display_name;
    const std::size_t split = name.rfind(" / ");
    if (split != std::string::npos)
        name = name.substr(split + 3);
    if (name.empty() || name == "Application" ||
        (menu_title && name == menu_title))
        return {};
    return QString::fromStdString(name);
}

bool menu_has_action_id(QMenu* menu, const QString& id) {
    if (!menu)
        return false;
    const auto present = menu->actions();
    return std::any_of(present.begin(), present.end(), [&](QAction* existing) {
        return existing && !existing->isSeparator() &&
            existing->data().toString() == id;
    });
}

bool workspace_request_succeeded(docking::workspace_request_result_t result) noexcept {
    using result_t = docking::workspace_request_result_t;
    return result == result_t::completed || result == result_t::queued ||
        result == result_t::unchanged;
}

std::string workspace_request_message(docking::workspace_request_result_t result,
                                      const char* failure) {
    using result_t = docking::workspace_request_result_t;
    switch (result) {
    case result_t::completed:
    case result_t::queued:
    case result_t::unchanged:
        return {};
    case result_t::busy:
        return "Another workspace layout transaction is already in progress";
    case result_t::invalid_name:
        return "Workspace names must be 1-64 ASCII letters, numbers, spaces, hyphens or underscores, without leading, trailing or repeated spaces";
    case result_t::already_exists:
        return "A saved workspace with this exact name already exists";
    case result_t::not_found:
        return "The selected saved workspace no longer exists";
    case result_t::unavailable:
        return "The workspace operation is unavailable until the DockSpace is ready";
    case result_t::failed:
        break;
    }
    return failure ? failure : "The workspace operation failed";
}

aida::ui::capability_state_t workspace_load_capability(
    const docking::user_workspace_descriptor_t& retained,
    layout::WorkspacePersistenceController* persistence) {
    using aida::ui::capability_state_t;
    if (!persistence)
        return capability_state_t::unavailable(
            "The workspace persistence service is not available");
    if (!persistence->user_layout_catalog_ready())
        return capability_state_t::unavailable(
            "The saved workspace catalog is still loading");
    const auto catalog = persistence->user_layout_catalog();
    if (!catalog)
        return capability_state_t::unavailable(
            "This saved workspace changed after it was presented; reopen the catalog");
    const auto current = std::find_if(catalog->begin(), catalog->end(),
        [&](const auto& item) {
            return item.name == retained.name &&
                item.generation == retained.generation;
        });
    if (current == catalog->end())
        return capability_state_t::unavailable(
            "This saved workspace changed after it was presented; reopen the catalog");
    if (current->active)
        return capability_state_t::unavailable(
            "This saved workspace is already active");
    if (persistence->operation_pending()) {
        const std::string status = persistence->operation_status();
        return capability_state_t::unavailable(status.empty()
            ? "Another workspace transaction is already running" : status);
    }
    return capability_state_t::available();
}

aida::ui::application_ui::retained_entity_context_t saved_workspace_context(
    const docking::user_workspace_descriptor_t& item,
    layout::WorkspacePersistenceController* persistence) {
    using namespace aida::ui;
    application_ui::retained_entity_context_t context;
    context.owner_id = "workspace.saved";
    context.entity_id = item.name;
    context.entity_generation = item.generation;
    context.validate_identity = [item, persistence] {
        return workspace_load_capability(item, persistence);
    };
    application_ui::retained_entity_action_t action;
    action.action_id = "workspace.load_named";
    action.capability = workspace_load_capability(item, persistence);
    action.invoke = [item, persistence]() -> action_handler_result_t {
        const auto capability = workspace_load_capability(item, persistence);
        if (!capability.enabled)
            return action_handler_result_t::failed(capability.disabled_reason);
        const auto result = persistence
            ? persistence->load_user_layout_exact(item.name, item.generation)
            : docking::workspace_request_result_t::unavailable;
        std::string detail = workspace_request_message(result, "Load workspace");
        if (result == docking::workspace_request_result_t::unavailable && persistence &&
            persistence->user_layout_catalog_ready()) {
            const auto catalog = persistence->user_layout_catalog();
            const bool exact_identity_exists = catalog && std::any_of(
                catalog->begin(), catalog->end(), [&](const auto& entry) {
                    return entry.name == item.name &&
                        entry.generation == item.generation;
                });
            if (!exact_identity_exists)
                detail = "The selected saved workspace changed after it was presented. Reopen the catalog and select its current generation.";
        }
        return workspace_request_succeeded(result)
            ? action_handler_result_t::completed(detail)
            : action_handler_result_t::failed(detail);
    };
    context.actions.push_back(std::move(action));
    return context;
}

}

ContextMenuController::ContextMenuController(
    aida::ui::stable_menu_id_t menu, ActionBridge* actions, QObject* parent)
    : QObject(parent), actions_(actions), menu_id_(std::move(menu)) {}

void ContextMenuController::show(aida::ui::interaction_context_t snapshot,
                                 aida::ui::context_menu_open_origin_t origin,
                                 const QPoint& global_pos, QWidget* parent) {
    close_active();
    aida::ui::application_ui::bump_interaction_generation();
    snapshot_ = std::move(snapshot);
    snapshot_.generation = aida::ui::application_ui::interaction_generation();
    request_.menu = menu_id_;
    request_.origin = origin;
    request_.context_generation = snapshot_.generation;

    auto* menu = new QMenu(parent);
    menu->setAttribute(Qt::WA_DeleteOnClose);
    menu->setObjectName(QStringLiteral("aida.context.") +
        QString::fromStdString(menu_id_.value()));
    menu->setToolTipsVisible(true);
    connect(menu, &QMenu::aboutToShow, this, &ContextMenuController::compose_now);
    connect(menu, &QMenu::triggered, this, [this](QAction* action) {
        if (action)
            execute_item(action->data().toString());
    });
    connect(menu, &QObject::destroyed, this, [this] { active_menu_ = nullptr; });
    active_menu_ = menu;
    menu->popup(global_pos);
}

void ContextMenuController::close_active() {
    if (active_menu_)
        active_menu_->close();
    active_menu_ = nullptr;
}

void ContextMenuController::compose_now() {
    using namespace aida::ui;
    QMenu* menu = active_menu_;
    if (!menu)
        return;
    const auto abort_show = [&menu] {
        menu->clear();
        menu->deleteLater();
    };
    if (application_ui::interaction_generation() != request_.context_generation) {
        diag::log_tagged_fmt("qt_menu_bridge",
            "context_menu_stale_at_show menu=%s generation=%llu live=%llu",
            menu_id_.value().c_str(),
            static_cast<unsigned long long>(request_.context_generation),
            static_cast<unsigned long long>(application_ui::interaction_generation()));
        abort_show();
        return;
    }
    context_menu_presenter_t presenter(application_ui::context_menu_catalog(),
        application_ui::action_registry(), &application_ui::shortcut_resolver());
    const auto presentation = presenter.compose(request_, snapshot_);
    if (!presentation.ready()) {
        diag::log_tagged_fmt("qt_menu_bridge",
            "context_menu_compose_rejected menu=%s status=%d detail=%s",
            menu_id_.value().c_str(), static_cast<int>(presentation.status),
            presentation.detail.c_str());
        abort_show();
        return;
    }
    clear_menu(menu);
    if (presentation.sections.empty()) {
        add_text_row(menu, QStringLiteral("No actions available for this selection"),
            QStringLiteral("aida.context.empty"));
        return;
    }
    bool first_row = true;
    for (const auto& section : presentation.sections) {
        if (!section.label.empty()) {
            add_text_row(menu, QString::fromStdString(section.label),
                QStringLiteral("aida.context.section.") +
                    QString::fromStdString(section.id.value()));
        } else if (!first_row) {
            menu->addSeparator();
        }
        first_row = false;
        for (const auto& action : section.actions) {
            const QString action_id = QString::fromStdString(action.action.value());
            QString text = QString::fromStdString(action.label);
            if (!action.shortcut_hint.empty())
                text += u'\t' + QString::fromStdString(action.shortcut_hint);
            auto* item = new QAction(text, menu);
            item->setAutoRepeat(false);
            item->setObjectName(QStringLiteral("aida.") + action_id +
                QStringLiteral(".context"));
            item->setData(action_id);
            item->setEnabled(action.enabled);
            const bool checkable =
                action.check_state != action_check_state_t::not_checkable;
            item->setCheckable(checkable);
            if (checkable)
                item->setChecked(action.check_state != action_check_state_t::unchecked);
            if (!action.icon_semantic.empty()) {
                const QIcon icon = aida::qt::theme::icons::icon(
                    QString::fromStdString(action.icon_semantic));
                if (!icon.isNull())
                    item->setIcon(icon);
            }
            QString tooltip = action.enabled
                ? QString::fromStdString(action.description)
                : (action.disabled_reason.empty()
                       ? QString::fromStdString(action.description)
                       : QString::fromStdString(action.disabled_reason));
            if (action.check_state == action_check_state_t::mixed)
                tooltip += QStringLiteral(" (mixed)");
            item->setToolTip(tooltip);
            item->setShortcutVisibleInContextMenu(true);
            item->setProperty("aida.undoable", action.undoable);
            item->setProperty("aida.reviewable", action.reviewable);
            menu->addAction(item);
        }
    }
}

void ContextMenuController::execute_item(const QString& action_id) {
    using namespace aida::ui;
    if (action_id.isEmpty())
        return;
    auto& registry = application_ui::action_registry();
    const auto id = stable_action_id_t(action_id.toStdString());
    if (application_ui::interaction_generation() != request_.context_generation) {
        action_execution_result_t stale;
        stale.status = action_execution_status_t::rejected;
        stale.action = id;
        stale.message = "Context menu selection is stale";
        diag::log_tagged_fmt("qt_menu_bridge",
            "context_menu_execute_stale menu=%s action=%s",
            menu_id_.value().c_str(), id.value().c_str());
        application_ui::publish_action_execution_failure(id.c_str(), stale,
            action_invocation_source_t::context_menu);
        return;
    }
    context_menu_presenter_t presenter(application_ui::context_menu_catalog(),
        registry, &application_ui::shortcut_resolver());
    action_invocation_t invocation{snapshot_};
    invocation.source = action_invocation_source_t::context_menu;
    invocation.invocation_id = application_ui::allocate_invocation_id();
    auto result = presenter.execute(request_, id, invocation);
    actions_->finalize(action_id, result, action_invocation_source_t::context_menu,
                       invocation.context);
}

QString MenuBridge::top_menu_object_name(top_menu_t which) {
    switch (which) {
    case top_menu_t::file: return QStringLiteral("aida.menu.file");
    case top_menu_t::edit: return QStringLiteral("aida.menu.edit");
    case top_menu_t::view: return QStringLiteral("aida.menu.view");
    case top_menu_t::navigate: return QStringLiteral("aida.menu.navigate");
    case top_menu_t::analysis: return QStringLiteral("aida.menu.analysis");
    case top_menu_t::debugger_: return QStringLiteral("aida.menu.debugger");
    case top_menu_t::memory: return QStringLiteral("aida.menu.memory");
    case top_menu_t::types: return QStringLiteral("aida.menu.types");
    case top_menu_t::network: return QStringLiteral("aida.menu.network");
    case top_menu_t::workspace: return QStringLiteral("aida.menu.workspace");
    case top_menu_t::tools: return QStringLiteral("aida.menu.tools");
    case top_menu_t::ai: return QStringLiteral("aida.menu.ai");
    case top_menu_t::help: return QStringLiteral("aida.menu.help");
    }
    return QStringLiteral("aida.menu.unknown");
}

MenuBridge::MenuBridge(ActionBridge* actions, InteractionContextProvider* context,
                       QObject* parent)
    : QObject(parent), actions_(actions), context_(context) {}

QMenuBar* MenuBridge::installBar(docking::AidaDockHost* host) {
    if (bar_)
        return bar_;
    host_ = host;
    bar_ = new QMenuBar();
    bar_->setObjectName(QStringLiteral("aida.menu_bar"));
    struct menu_def_t {
        top_menu_t which;
        const char* title;
    };
    static constexpr menu_def_t defs[] = {
        {top_menu_t::file, "&File"},
        {top_menu_t::edit, "&Edit"},
        {top_menu_t::view, "&View"},
        {top_menu_t::navigate, "&Navigate"},
        {top_menu_t::analysis, "&Analysis"},
        {top_menu_t::debugger_, "&Debugger"},
        {top_menu_t::memory, "&Memory"},
        {top_menu_t::types, "T&ypes"},
        {top_menu_t::network, "Networ&k"},
        {top_menu_t::workspace, "&Workspace"},
        {top_menu_t::tools, "&Tools"},
        {top_menu_t::ai, "A&I"},
        {top_menu_t::help, "&Help"},
    };
    for (const auto& def : defs) {
        QMenu* menu = bar_->addMenu(QString::fromLatin1(def.title));
        menu->setObjectName(top_menu_object_name(def.which));
        menu->setToolTipsVisible(true);
        menus_[def.which] = menu;
        const QString menu_name = top_menu_object_name(def.which);
        chrome::ChromeVisibilityTracer::install(menu, menu_name);
        connect(menu, &QMenu::aboutToShow, this, [this, which = def.which, menu_name] {
            QElapsedTimer menu_timer;
            menu_timer.start();
            QMenuBar* bar = bar_;
            QWidget* strip = bar ? bar->parentWidget() : nullptr;
            diag::log_tagged_fmt("qt_menu_bridge",
                "top_menu_aboutToShow_enter menu=%s bar_vis=%d bar_h=%d strip_vis=%d strip_h=%d popup=%d",
                menu_name.toUtf8().constData(),
                (bar && bar->isVisible()) ? 1 : 0,
                bar ? bar->height() : -1,
                (strip && strip->isVisible()) ? 1 : 0,
                strip ? strip->height() : -1,
                QApplication::activePopupWidget() ? 1 : 0);
            bool rebuilt = false;
            switch (which) {
            case top_menu_t::view: rebuilt = rebuild_view_menu(); break;
            case top_menu_t::types: rebuilt = rebuild_types_menu(); break;
            case top_menu_t::workspace: rebuilt = rebuild_workspace_menu(); break;
            default: rebuilt = rebuild_registered_menu(which); break;
            }
            QMenu* target = this->menu(which);
            const int visible_actions = target ? static_cast<int>(std::count_if(
                target->actions().begin(), target->actions().end(),
                [](QAction* a) { return a && a->isVisible(); })) : -1;
            diag::log_tagged_fmt("qt_menu_bridge",
                "top_menu_aboutToShow_exit menu=%s actions=%d visible_actions=%d rebuilt=%d elapsed_ms=%lld bar_vis=%d bar_h=%d strip_vis=%d strip_h=%d",
                menu_name.toUtf8().constData(),
                target ? static_cast<int>(target->actions().size()) : -1,
                visible_actions,
                rebuilt ? 1 : 0,
                static_cast<long long>(menu_timer.elapsed()),
                (bar && bar->isVisible()) ? 1 : 0,
                bar ? bar->height() : -1,
                (strip && strip->isVisible()) ? 1 : 0,
                strip ? strip->height() : -1);
        });
        connect(menu, &QMenu::aboutToHide, this, [menu_name] {
            diag::log_tagged_fmt("qt_menu_bridge",
                "top_menu_aboutToHide menu=%s popup_still_active=%d",
                menu_name.toUtf8().constData(),
                QApplication::activePopupWidget() ? 1 : 0);
        });
    }
    actions_->ensure_current();
    if (host_) {
        connect(host_, &docking::AidaDockHost::layoutDirty, this, [this] {
            invalidate_menu_structure();
        });
        if (auto* persistence = host_->persistence()) {
            connect(persistence,
                    &layout::WorkspacePersistenceController::activeWorkspaceChanged,
                    this, [this] { invalidate_menu_structure(); });
            connect(persistence,
                    &layout::WorkspacePersistenceController::userCatalogChanged,
                    this, [this] { invalidate_menu_structure(); });
        }
    }
    connect(actions_, &ActionBridge::actions_rebuilt, this, [this] {
        invalidate_menu_structure();
    });
    diag::log_tagged("qt_menu_bridge", "menu_bar_installed menus=13");
    return bar_;
}

QMenu* MenuBridge::menu(top_menu_t which) const {
    const auto found = menus_.find(which);
    return found == menus_.end() ? nullptr : found->second;
}

void MenuBridge::register_menu_contents(top_menu_t which,
                                        std::vector<menu_section_spec_t> sections) {
    registered_[which] = std::move(sections);
    invalidate_menu_structure();
}

bool MenuBridge::menu_cache_hit(top_menu_t which) const {
    const auto found = menu_stamps_.find(which);
    if (found == menu_stamps_.end() || !found->second.valid)
        return false;
    const menu_stamp_t& stamp = found->second;
    return stamp.action_revision ==
            aida::ui::application_ui::action_registry().revision() &&
        stamp.shortcut_revision ==
            aida::ui::application_ui::shortcut_resolver().revision() &&
        stamp.structure_revision == structure_revision_ &&
        stamp.context_generation == aida::ui::application_ui::interaction_generation();
}

void MenuBridge::note_menu_built(top_menu_t which) {
    menu_stamp_t stamp;
    stamp.action_revision = aida::ui::application_ui::action_registry().revision();
    stamp.shortcut_revision = aida::ui::application_ui::shortcut_resolver().revision();
    stamp.structure_revision = structure_revision_;
    stamp.context_generation = aida::ui::application_ui::interaction_generation();
    stamp.valid = true;
    menu_stamps_[which] = stamp;
}

void MenuBridge::invalidate_menu_structure() {
    ++structure_revision_;
}

void MenuBridge::refresh_menu_states(QMenu* target) {
    if (!target)
        return;
    const QList<QAction*> items = target->actions();
    for (QAction* item : items) {
        if (!item)
            continue;
        if (QMenu* sub = item->menu()) {
            if (sub->objectName().startsWith(QStringLiteral("aida.menu.view.category.")))
                refresh_menu_states(sub);
            continue;
        }
        if (item->isSeparator())
            continue;
        if (item->data().toString().isEmpty())
            continue;
        actions_->refresh(item);
    }
}

bool MenuBridge::rebuild_registered_menu(top_menu_t which) {
    QMenu* target = menu(which);
    if (!target)
        return false;
    actions_->ensure_current();
    if (menu_cache_hit(which)) {
        refresh_menu_states(target);
        return false;
    }
    clear_menu(target);
    const auto found = registered_.find(which);
    if (found != registered_.end())
        append_spec_items(target, found->second);
    append_registry_entries(which, target);
    const auto has_items = std::any_of(target->actions().begin(), target->actions().end(),
        [](QAction* action) {
            return action && action->isVisible() && !action->isSeparator() &&
                !action->data().toString().isEmpty();
        });
    if (!has_items)
        add_text_row(target, QStringLiteral("No actions available"),
            top_menu_object_name(which) + QStringLiteral(".empty"));
    note_menu_built(which);
    return true;
}

void MenuBridge::append_registry_entries(top_menu_t which, QMenu* target) {
    using namespace aida::ui;
    if (!target)
        return;
    auto& registry = application_ui::action_registry();
    const auto context = context_->current();
    struct collected_item_t {
        std::string id;
        std::string label;
    };
    struct collected_group_t {
        std::string display_name;
        std::vector<collected_item_t> items;
    };
    std::vector<collected_group_t> groups;
    registry.for_each([&](const application_action_descriptor_t& descriptor) {
        if (!any(descriptor.surfaces & action_surface_t::application_menu))
            return;
        const auto mapped = top_menu_for_action_id(descriptor.id.value());
        if (!mapped || *mapped != which)
            return;
        const auto state = registry.evaluate(descriptor.id, context);
        if (!state.capability.visible)
            return;
        const QString id = QString::fromStdString(descriptor.id.value());
        if (menu_has_action_id(target, id))
            return;
        collected_group_t* group = nullptr;
        for (auto& candidate : groups) {
            if (candidate.display_name == descriptor.category.display_name) {
                group = &candidate;
                break;
            }
        }
        if (!group) {
            groups.push_back({descriptor.category.display_name, {}});
            group = &groups.back();
        }
        group->items.push_back({descriptor.id.value(), descriptor.label});
    });
    if (groups.empty())
        return;
    const char* title = top_menu_plain_title(which);
    std::stable_sort(groups.begin(), groups.end(),
        [&](const collected_group_t& lhs, const collected_group_t& rhs) {
            const bool lhs_primary = registry_group_header(lhs.display_name, title).isEmpty();
            const bool rhs_primary = registry_group_header(rhs.display_name, title).isEmpty();
            return lhs_primary && !rhs_primary;
        });
    bool first_row = target->actions().isEmpty();
    for (auto& group : groups) {
        std::sort(group.items.begin(), group.items.end(),
            [](const collected_item_t& lhs, const collected_item_t& rhs) {
                if (lhs.label != rhs.label)
                    return lhs.label < rhs.label;
                return lhs.id < rhs.id;
            });
        const QString header = registry_group_header(group.display_name, title);
        if (!header.isEmpty())
            add_text_row(target, header,
                QStringLiteral("aida.menu.section.") + header);
        else if (!first_row)
            target->addSeparator();
        first_row = false;
        for (const auto& item : group.items) {
            QAction* action = actions_->menu_action(
                QString::fromStdString(item.id), {}, {}, target);
            if (action && action->isVisible())
                target->addAction(action);
        }
    }
}

void MenuBridge::append_spec_items(QMenu* target,
                                   const std::vector<menu_section_spec_t>& sections) {
    bool first_row = true;
    for (const auto& section : sections) {
        if (!section.label.empty())
            add_text_row(target, QString::fromStdString(section.label),
                QStringLiteral("aida.menu.section.") +
                    QString::fromStdString(section.label));
        else if (!first_row)
            target->addSeparator();
        first_row = false;
        for (const auto& item : section.items) {
            QAction* action = actions_->menu_action(
                QString::fromStdString(item.action_id),
                QString::fromStdString(item.label_override),
                QString::fromStdString(item.shortcut_override), target);
            if (action && action->isVisible())
                target->addAction(action);
        }
    }
}

void MenuBridge::append_view_entries(
    QMenu* target, std::optional<aida::qt::registry::view_category_t> only_category,
    bool group_by_category) {
    using namespace aida::ui;
    using aida::qt::registry::menu_entry_t;
    if (!host_ || !host_->registry())
        return;
    std::vector<menu_entry_t> entries;
    host_->for_each_menu_entry([&](const menu_entry_t& entry) {
        if (!only_category || entry.category == *only_category)
            entries.push_back(entry);
    });
    const auto context = context_->current();
    auto& registry = application_ui::action_registry();

    const auto render_entry = [&](QMenu* into, const menu_entry_t& entry) {
        const std::string action_id_str = application_ui::view_action_id(entry.id);
        const QString action_id = QString::fromStdString(action_id_str);
        const auto* descriptor = registry.find(stable_action_id_t(action_id_str));
        if (!descriptor)
            return;
        const auto state = registry.evaluate(descriptor->id, context);
        if (!state.capability.visible)
            return;
        QString text = QString::fromStdString(entry.label);
        const QString hint = actions_->shortcut_hint(action_id, context);
        if (!hint.isEmpty())
            text += u'\t' + hint;
        auto* item = new QAction(text, into);
        item->setAutoRepeat(false);
        item->setObjectName(QStringLiteral("aida.") + action_id +
            QStringLiteral(".menu"));
        item->setData(action_id);
        item->setCheckable(true);
        item->setChecked(entry.open);
        const bool enabled = entry.enabled && state.capability.enabled;
        item->setEnabled(enabled);
        if (!enabled) {
            const std::string& reason = !entry.disabled_reason.empty()
                ? entry.disabled_reason : state.capability.disabled_reason;
            if (!reason.empty())
                item->setToolTip(QString::fromStdString(reason));
        } else {
            item->setToolTip(QString::fromStdString(descriptor->description));
        }
        ActionBridge* bridge = actions_;
        connect(item, &QAction::triggered, bridge, [bridge, action_id](bool) {
            bridge->dispatch(action_id, action_invocation_source_t::application_menu);
        });
        into->addAction(item);
    };

    std::size_t begin = 0;
    while (begin < entries.size()) {
        const auto category = entries[begin].category;
        std::size_t end = begin;
        std::size_t open_count = 0;
        while (end < entries.size() && entries[end].category == category) {
            if (entries[end].open)
                ++open_count;
            ++end;
        }
        if (group_by_category) {
            QString title = QString::fromLatin1(aida::qt::registry::category_label(category));
            title += QStringLiteral("  (%1/%2)")
                .arg(static_cast<qulonglong>(open_count))
                .arg(static_cast<qulonglong>(end - begin));
            QMenu* submenu = target->addMenu(title);
            submenu->setObjectName(QStringLiteral("aida.menu.view.category.") +
                QString::fromLatin1(aida::qt::registry::category_label(category)));
            submenu->setToolTipsVisible(true);
            for (std::size_t index = begin; index < end; ++index)
                render_entry(submenu, entries[index]);
        } else {
            for (std::size_t index = begin; index < end; ++index)
                render_entry(target, entries[index]);
        }
        begin = end;
    }
}

bool MenuBridge::rebuild_view_menu() {
    QMenu* target = menu(top_menu_t::view);
    if (!target)
        return false;
    actions_->ensure_current();
    if (menu_cache_hit(top_menu_t::view)) {
        refresh_menu_states(target);
        return false;
    }
    clear_menu(target);
    const auto found = registered_.find(top_menu_t::view);
    if (found != registered_.end())
        append_spec_items(target, found->second);
    append_view_entries(target, std::nullopt, true);
    note_menu_built(top_menu_t::view);
    return true;
}

bool MenuBridge::rebuild_types_menu() {
    QMenu* target = menu(top_menu_t::types);
    if (!target)
        return false;
    actions_->ensure_current();
    if (menu_cache_hit(top_menu_t::types)) {
        refresh_menu_states(target);
        return false;
    }
    clear_menu(target);
    const auto found = registered_.find(top_menu_t::types);
    if (found != registered_.end())
        append_spec_items(target, found->second);
    append_view_entries(target, aida::qt::registry::view_category_t::types, false);
    note_menu_built(top_menu_t::types);
    return true;
}

bool MenuBridge::rebuild_workspace_menu() {
    using namespace aida::ui;
    QMenu* target = menu(top_menu_t::workspace);
    if (!target)
        return false;
    actions_->ensure_current();
    if (menu_cache_hit(top_menu_t::workspace)) {
        refresh_menu_states(target);
        return false;
    }
    clear_menu(target);
    saved_menu_built_ = false;
    const auto found = registered_.find(top_menu_t::workspace);
    if (found != registered_.end() && !found->second.empty()) {
        append_spec_items(target, found->second);
        target->addSeparator();
    }
    if (!host_ || !host_->persistence()) {
        add_text_row(target, QStringLiteral("Workspace layout is not available"),
            QStringLiteral("aida.workspace.unavailable"));
        note_menu_built(top_menu_t::workspace);
        return true;
    }
    auto* persistence = host_->persistence();
    const auto identity = persistence->active_identity();
    const auto preset_name = docking::preset_descriptor(identity.preset).display_name;
    QString active_text = QStringLiteral("Active: %1 / %2")
        .arg(QString::fromLatin1(preset_name.data(),
                                 static_cast<qsizetype>(preset_name.size())))
        .arg(identity.kind == docking::workspace_identity_kind_t::user
                 ? QString::fromStdString(identity.user_name)
                 : QStringLiteral("Built-in"));
    add_text_row(target, active_text, QStringLiteral("aida.workspace.identity"));
    target->addSeparator();

    std::size_t preset_count = 0;
    const auto* preset_list = docking::presets(preset_count);
    for (std::size_t index = 0; index < preset_count; ++index) {
        const auto& preset = preset_list[index];
        if (preset.id == docking::workspace_preset_t::safe)
            continue;
        const std::string action_id =
            std::string("workspace.switch.") + std::string(preset.stable_id);
        QAction* item = actions_->menu_action(QString::fromStdString(action_id),
            QString::fromLatin1(preset.display_name.data(),
                                static_cast<qsizetype>(preset.display_name.size())),
            {}, target);
        if (!item)
            continue;
        item->setCheckable(true);
        item->setChecked(identity.kind == docking::workspace_identity_kind_t::built_in &&
            identity.preset == preset.id);
        target->addAction(item);
    }
    target->addSeparator();

    const bool locked = host_->layout_locked();
    if (QAction* lock = actions_->menu_action(QStringLiteral("workspace.lock"),
            locked ? QStringLiteral("Unlock Layout") : QStringLiteral("Lock Layout"),
            {}, target))
        target->addAction(lock);
    if (QAction* save_active = actions_->menu_action(
            QStringLiteral("workspace.save_active"), {}, {}, target))
        target->addAction(save_active);
    if (QAction* save_as = actions_->menu_action(
            QStringLiteral("workspace.save_as"), {}, {}, target))
        target->addAction(save_as);

    QMenu* saved = target->addMenu(QStringLiteral("Saved Workspaces"));
    saved->setObjectName(QStringLiteral("aida.workspace.menu.saved_workspaces"));
    saved->setToolTipsVisible(true);
    connect(saved, &QMenu::aboutToShow, this, [this, saved] {
        rebuild_saved_workspaces(saved);
    });
    rebuild_saved_workspaces(saved);
    note_menu_built(top_menu_t::workspace);
    return true;
}

void MenuBridge::rebuild_saved_workspaces(QMenu* submenu) {
    using namespace aida::ui;
    if (!submenu)
        return;
    if (saved_menu_built_ && saved_menu_structure_revision_ == structure_revision_)
        return;
    clear_menu(submenu);
    auto* persistence = host_ ? host_->persistence() : nullptr;
    const auto catalog = persistence ? persistence->user_layout_catalog() : nullptr;
    if (!persistence || !catalog || catalog->empty()) {
        add_text_row(submenu, QStringLiteral("No saved workspaces"),
            QStringLiteral("aida.workspace.saved.empty"));
        saved_menu_built_ = true;
        saved_menu_structure_revision_ = structure_revision_;
        return;
    }
    for (const auto& item : *catalog) {
        const auto retained = saved_workspace_context(item, persistence);
        const auto presentation = application_ui::present_retained_entity_action(
            "workspace.load_named", retained);
        const QString name = QString::fromStdString(item.name);
        auto* entry = new QAction(name, submenu);
        entry->setAutoRepeat(false);
        entry->setObjectName(QStringLiteral("aida.workspace.saved.") + name);
        entry->setData(QStringLiteral("workspace.load_named"));
        entry->setEnabled(presentation.enabled);
        const auto base_name = docking::preset_descriptor(item.base_preset).display_name;
        const QString base_text = QString::fromLatin1(base_name.data(),
            static_cast<qsizetype>(base_name.size()));
        QString tooltip = item.active
            ? QStringLiteral("Active workspace, based on %1").arg(base_text)
            : QStringLiteral("Based on %1").arg(base_text);
        if (!presentation.enabled) {
            const QString reason = presentation.disabled_reason.empty()
                ? QStringLiteral("The retained workspace action is unavailable.")
                : QString::fromStdString(presentation.disabled_reason);
            tooltip += QStringLiteral("\n") + reason;
        }
        entry->setToolTip(tooltip);
        connect(entry, &QAction::triggered, this, [this, item, persistence, name](bool) {
            const auto retained = saved_workspace_context(item, persistence);
            const auto result = application_ui::execute_retained_entity_action(
                "workspace.load_named", action_invocation_source_t::application_menu,
                retained);
            if (!result.executed()) {
                Q_EMIT saved_workspace_load_failed(name, item.generation,
                    result.message.empty()
                        ? QStringLiteral("The selected saved workspace could not be loaded.")
                        : QString::fromStdString(result.message));
            }
        });
        submenu->addAction(entry);
    }
    saved_menu_built_ = true;
    saved_menu_structure_revision_ = structure_revision_;
}

void MenuBridge::show_context_menu(const aida::ui::stable_menu_id_t& menu_id,
                                   aida::ui::interaction_context_t snapshot,
                                   aida::ui::context_menu_open_origin_t origin,
                                   const QPoint& global_pos, QWidget* parent) {
    const QString key = QString::fromStdString(menu_id.value());
    ContextMenuController* controller = context_controllers_.value(key, nullptr);
    if (!controller) {
        controller = new ContextMenuController(menu_id, actions_, this);
        context_controllers_.insert(key, controller);
    }
    controller->show(std::move(snapshot), origin, global_pos, parent);
}

void MenuBridge::show_retained_entity_menu(
    const aida::ui::application_ui::retained_entity_context_t& context,
    aida::ui::context_menu_open_origin_t origin, const QPoint& global_pos,
    QWidget* parent) {
    if (context.owner_id.empty() || context.entity_id.empty() || context.actions.empty())
        return;
    auto snapshot = aida::ui::application_ui::make_retained_entity_context(context);
    const aida::ui::stable_menu_id_t menu = context.menu.empty()
        ? aida::ui::stable_menu_id_t("menu.retained.entity")
        : context.menu;
    show_context_menu(menu, std::move(snapshot), origin, global_pos, parent);
}

}
