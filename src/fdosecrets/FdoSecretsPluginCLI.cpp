#include "FdoSecretsPluginCLI.h"

#include "cli/LineReader.h"
#include "cli/Utils.h"
#include "core/Entry.h"
#include "core/Group.h"
#include "fdosecrets/FdoSecretsSettings.h"
#include "fdosecrets/dbus/DBusClient.h"

FdoSecretsPluginCLI::FdoSecretsPluginCLI(LineReader* lineReader)
    : FdoSecretsPlugin{lineReader}
    , m_lineReader(lineReader)
{
}

size_t FdoSecretsPluginCLI::requestEntriesRemove(const FdoSecrets::DBusClientPtr& client,
                                                 const QString& name,
                                                 const QList<Entry*>& entries,
                                                 bool permanent) const
{
    LineReaderGuard guard{m_lineReader};
    auto& out = Utils::STDOUT;

    if (entries.isEmpty()) {
        return 0;
    }

    if (FdoSecrets::settings()->confirmDeleteItem() && confirmDeleteEntries(client, name, entries, permanent)) {
        return 0;
    }

    QList<Entry*> selectedEntries;
    // Find references to entries and prompt for direction if necessary
    for (auto entry : entries) {
        if (permanent) {
            auto references = entry->database()->rootGroup()->referencesRecursive(entry);
            if (!references.isEmpty()) {
                // Ignore references that are part of this cohort
                for (auto e : entries) {
                    references.removeAll(e);
                }

                // Prompt the user on what to do with the reference (Overwrite, Delete, Skip)
                out << QObject::tr("Entry \"%1\" has %2 reference(s).", "", references.size())
                           .arg(entry->resolvePlaceholder(entry->title()))
                           .arg(references.size())
                    << Qt::endl;
                int choice = userAction(QObject::tr("Replace references to entry? %1"),
                                        {QObject::tr("[O]verwrite references with values"),
                                         QObject::tr("[S]kip this entry"),
                                         QObject::tr("[D]elete anyway")},
                                        {QObject::tr("o|overwrite"), QObject::tr("s|skip"), QObject::tr("d|delete")});

                switch (choice) {
                case 0:
                    for (auto ref : references) {
                        ref->replaceReferencesWithValues(entry);
                    }
                    break;
                case 1:
                    continue;
                case 2:
                    break;
                case -1:
                default:
                    return 0;
                }
            }
        }

        // Marked for deletion
        selectedEntries << entry;
    }

    for (auto entry : asConst(selectedEntries)) {
        if (permanent) {
            delete entry;
        } else {
            entry->database()->recycleEntry(entry);
        }
    }

    return selectedEntries.size();
}

enum Action
{
    Rejected,
    AllowSelected,
    AllowAll,
    DenyAll,
};

bool FdoSecretsPluginCLI::requestEntriesUnlock(const FdoSecrets::DBusClientPtr& client,
                                               const QString&,
                                               const QList<Entry*>& entries,
                                               QHash<Entry*, AuthDecision>& decisions,
                                               AuthDecision& forFutureEntries) const
{
    LineReaderGuard guard{m_lineReader};
    QString app = QObject::tr("%1 (PID: %2)").arg(client->name()).arg(client->pid());
    auto& out = Utils::STDOUT;

    auto decision = AuthDecision::Undecided;
    forFutureEntries = AuthDecision::Undecided;
    auto action = Rejected;
    QString actionStr = "Reject";
    out << QObject::tr("%1 is requesting access to the following entries:").arg(app) << Qt::endl;
    int i = 1;
    for (const auto& entry : entries) {
        out << QObject::tr("%1. %2 (username: %3)").arg(i).arg(entry->title()).arg(entry->username()) << Qt::endl;
    }

    int choice = userAction(
        QObject::tr("Choose action: %1"),
        {QObject::tr("[A]llow All"), QObject::tr("[D]eny All"), QObject::tr("Allow [S]elected")},
        {QObject::tr("a|allow|allow all"), QObject::tr("d|deny|deny all"), QObject::tr("s|selected|allow selected")});

    switch (choice) {
    case 0:
        action = AllowAll;
        actionStr = QObject::tr("Allow All");
        decision = AuthDecision::AllowedOnce;
        break;
    case 1:
        action = DenyAll;
        actionStr = QObject::tr("Deny All");
        decision = AuthDecision::DeniedOnce;
        break;
    case 2:
        action = AllowSelected;
        actionStr = QObject::tr("Allow Selected");
        decision = AuthDecision::AllowedOnce;
        break;
    case -1:
    default:
        return false;
    }

    for (const auto& entry : entries) {
        bool undecided = false;
        if (action == AllowSelected) {
            choice = userAction(QObject::tr("Allow %1 access to \"%2\" (username: %3)? %4")
                                    .arg(app)
                                    .arg(entry->title())
                                    .arg(entry->username()),
                                {QObject::tr("[Y]es"), QObject::tr("[N]o")},
                                {QObject::tr("y|yes"), QObject::tr("n|no")});
            if (choice == -1) {
                return false;
            }

            undecided = choice != 0;
        }

        decisions[entry] = undecided ? AuthDecision::Undecided : decision;
    }

    QString warning;
    if (action == AllowAll || action == DenyAll) {
        warning = QObject::tr("WARNING: this will concern ALL entries, not only the ones listed above!");
    } else if (action == AllowSelected) {
        warning = QObject::tr("This will only concern entries selected above!");
    }

    choice = userAction(QObject::tr("Do you want to remember this action (%1) for all future requests from %2? %4\n%3")
                            .arg(actionStr)
                            .arg(app)
                            .arg(warning),
                        {QObject::tr("[Y]es"), QObject::tr("[N]o")},
                        {QObject::tr("y|yes"), QObject::tr("n|no")});

    switch (choice) {
    case 0:
        if (action == AllowSelected) {
            decision = AuthDecision::Allowed;
        } else if (action == AllowAll) {
            decision = AuthDecision::Allowed;
            forFutureEntries = AuthDecision::Allowed;
        } else if (action == DenyAll) {
            decision = AuthDecision::Denied;
            forFutureEntries = AuthDecision::Denied;
        }

        for (const auto& entry : entries) {
            if (decisions.value(entry) != AuthDecision::Undecided) {
                decisions[entry] = decision;
            }
        }
        break;

    case 1:
        break;

    case -1:
    default:
        return false;
    }

    return true;
}

bool FdoSecretsPluginCLI::confirmDeleteEntries(const FdoSecrets::DBusClientPtr& client,
                                               const QString& name,
                                               const QList<Entry*>& entries,
                                               bool permanent) const
{
    QString app = QObject::tr("%1 (PID: %2)").arg(client->name()).arg(client->pid());
    auto& out = Utils::STDOUT;

    out << QObject::tr("%1 is requesting %2 removal of the following entries from database \"%3\":")
               .arg(app)
               .arg(permanent ? QObject::tr("permanent") : "")
               .arg(name)
        << Qt::endl;
    int i = 1;
    for (const auto& entry : entries) {
        out << "\t" << QObject::tr("%1. %2").arg(i).arg(entry->title()) << Qt::endl;
    }

    out << Qt::endl;

    int choice = userAction(QObject::tr("Choose action: %1"),
                            {QObject::tr("[A]llow"), QObject::tr("[D]eny")},
                            {QObject::tr("a|allow"), QObject::tr("d|deny")});
    return choice == 0;
}

int FdoSecretsPluginCLI::userAction(const QString& message,
                                    const QStringList& actions,
                                    const QStringList& matches) const
{
    Q_ASSERT(actions.size() == matches.size());
    auto& out = Utils::STDOUT;
    auto& in = Utils::STDIN;

    QString availableActions = actions.join(" | ");
    out << message.arg(availableActions) << Qt::endl;

    QString input;
    while (true) {
        in >> input;
        if (in.atEnd()) {
            return -1;
        }

        auto clean = input.trimmed().toLower();
        int i = 0;
        for (const auto& action : matches) {
            for (const auto& match : action.split("|")) {
                if (clean == match.trimmed().toLower()) {
                    return i;
                }
            }
            ++i;
        }

        out << QObject::tr("Unknown response: %1. Please provide: %2").arg(input).arg(availableActions) << Qt::endl;
    }

    return -1;
}
