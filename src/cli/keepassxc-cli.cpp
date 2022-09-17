/*
 *  Copyright (C) 2020 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <QCommandLineParser>
#include <QFileInfo>

#include "Command.h"
#include "LineReader.h"
#include "Open.h"
#include "TextStream.h"
#include "Utils.h"
#include "config-keepassx.h"
#include "core/Bootstrap.h"
#include "core/Config.h"
#include "core/Metadata.h"
#include "core/Tools.h"
#include "crypto/Crypto.h"

#ifdef WITH_XC_FDOSECRETS
#include "fdosecrets/FdoSecretsPluginCLI.h"
#endif

#ifdef WITH_XC_SSHAGENT
#include "sshagent/SSHAgent.h"
#endif

#if defined(WITH_ASAN) && defined(WITH_LSAN)
#include <sanitizer/lsan_interface.h>
#endif

QString getPrompt(const Database* currentDatabase, bool withFdoSecrets = false, bool withSSHAgent = false)
{
    QString prompt;
    if (withFdoSecrets || withSSHAgent) {
        prompt += "[";
#ifdef WITH_XC_FDOSECRETS
        if (withFdoSecrets) {
            prompt += "F";
        }
#endif

#ifdef WITH_XC_SSHAGENT
        if (withSSHAgent) {
            prompt += "S";
        }
#endif
        prompt += "] ";
    }

    if (currentDatabase) {
        prompt += currentDatabase->metadata()->name();
        if (prompt.isEmpty()) {
            prompt += QFileInfo(currentDatabase->filePath()).fileName();
        }
    }
    prompt += "> ";
    return prompt;
}

int enterInteractiveMode(QCoreApplication& app,
                         const QStringList& arguments,
                         bool withFdoSecrets = false,
                         bool withSSHAgent = false)
{
    auto& err = Utils::STDERR;
    // Replace command list with interactive version
    Commands::setupCommands(true);

    Open openCmd;

    // Already read, here just to avoid unknown option errors
#ifdef WITH_XC_FDOSECRETS
    openCmd.options.append(Command::FdoSecretsOption);
#endif
#ifdef WITH_XC_SSHAGENT
    openCmd.options.append(Command::SSHAgentOption);
#endif

    QStringList openArgs(arguments);
    openArgs.removeFirst();
    if (openCmd.execute(openArgs) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    };

    QSharedPointer<Database> currentDatabase(openCmd.currentDatabase);

    QString prompt = getPrompt(currentDatabase.data(), withFdoSecrets, withSSHAgent);

    QScopedPointer<LineReader> reader;
#if defined(USE_READLINE)
    reader.reset(new ReadlineLineReader(prompt));
#else
    reader.reset(new SimpleLineReader(prompt));
#endif

#ifdef WITH_XC_FDOSECRETS
    FdoSecretsPluginCLI* fdoSS;
    if (withFdoSecrets) {
        fdoSS = new FdoSecretsPluginCLI(reader.data());
        QObject::connect(fdoSS, &FdoSecretsPlugin::error, [&err](const QString& message) {
            err << QObject::tr("Error in FDO Secrets: %1").arg(message) << endl;
        });

        QObject::connect(
            fdoSS, &FdoSecretsPlugin::requestShowNotification, [](const QString& message, const QString& title, int) {
                Utils::STDOUT << endl << "FDO Secrets: " << title << endl << message << endl;
            });

        fdoSS->updateServiceState();
        fdoSS->databaseUnlocked(currentDatabase->canonicalFilePath(), currentDatabase);
    }
#endif

#ifdef WITH_XC_SSHAGENT
    if (withSSHAgent) {
        if (!sshAgent()->isEnabled()) {
            err << QObject::tr("The SSH agent is not enabled.") << endl;
            return EXIT_FAILURE;
        }

        QObject::connect(sshAgent(), &SSHAgent::error, [&](const QString& message) {
            err << QObject::tr("Could not add OpenSSH key to the agent: %1").arg(message) << endl;
        });

        sshAgent()->databaseUnlocked(currentDatabase);
    }
#endif

    QObject::connect(reader.data(), &LineReader::finished, &app, QCoreApplication::quit);
    QObject::connect(reader.data(), &LineReader::readLine, [&](const QString command) {
        // Handle the input line
        QStringList args = Utils::splitCommandString(command);
        if (args.empty()) {
            return;
        }

        auto cmd = Commands::getCommand(args[0]);
        if (!cmd) {
            err << QObject::tr("Unknown command %1").arg(args[0]) << Qt::endl;
            return;
        } else if (cmd->name == "quit" || cmd->name == "exit") {
            app.quit();
            return;
        } else if (cmd->name == "open" || cmd->name == "close") {
            // unregister current database
            if (currentDatabase) {
#ifdef WITH_XC_FDOSECRETS
                if (withFdoSecrets) {
                    fdoSS->unregisterDatabase(currentDatabase->canonicalFilePath());
                }
#endif

#ifdef WITH_XC_SSHAGENT
                if (withSSHAgent) {
                    sshAgent()->databaseLocked(currentDatabase);
                }
#endif
            }
        }

        cmd->currentDatabase.swap(currentDatabase);
        cmd->execute(args);
        currentDatabase.swap(cmd->currentDatabase);

        if (cmd->name == "open") {
            // register new database
            if (currentDatabase) {
#ifdef WITH_XC_FDOSECRETS
                if (withFdoSecrets) {
                    fdoSS->databaseUnlocked(currentDatabase->canonicalFilePath(), currentDatabase);
                }
#endif

#ifdef WITH_XC_SSHAGENT
                if (withSSHAgent) {
                    sshAgent()->databaseUnlocked(currentDatabase);
                }
#endif
            }
        }

        // Update prompt
        prompt = getPrompt(currentDatabase.data(), withFdoSecrets, withSSHAgent);
    });

    auto ret = app.exec();

    if (currentDatabase) {
#ifdef WITH_XC_FDOSECRETS
        if (withFdoSecrets) {
            fdoSS->unregisterDatabase(currentDatabase->canonicalFilePath());
        }
#endif

#ifdef WITH_XC_SSHAGENT
        if (withSSHAgent) {
            sshAgent()->databaseLocked(currentDatabase);
        }
#endif
        currentDatabase->releaseData();
    }

    return ret;
}

int main(int argc, char** argv)
{
    if (!Crypto::init()) {
        qWarning("Fatal error while testing the cryptographic functions:\n%s", qPrintable(Crypto::errorString()));
        return EXIT_FAILURE;
    }

    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationVersion(KEEPASSXC_VERSION);

    Bootstrap::bootstrap(config()->get(Config::GUI_Language).toString());
    Utils::setDefaultTextStreams();
    Commands::setupCommands(false);

    auto& out = Utils::STDOUT;
    auto& err = Utils::STDERR;

    QStringList arguments;
    for (int i = 0; i < argc; ++i) {
        arguments << QString(argv[i]);
    }
    QCommandLineParser parser;

    QString description("KeePassXC command line interface.");
    description = description.append(QObject::tr("\n\nAvailable commands:\n"));
    for (auto& command : Commands::getCommands()) {
        description = description.append(command->getDescriptionLine());
    }
    parser.setApplicationDescription(description);

    parser.addPositionalArgument("command", QObject::tr("Name of the command to execute."));

    QCommandLineOption debugInfoOption(QStringList() << "debug-info", QObject::tr("Displays debugging information."));
    parser.addOption(debugInfoOption);
#ifdef WITH_XC_FDOSECRETS
    parser.addOption(Command::FdoSecretsOption);
#endif
#ifdef WITH_XC_SSHAGENT
    parser.addOption(Command::SSHAgentOption);
#endif

    parser.addHelpOption();
    parser.addVersionOption();
    // TODO : use the setOptionsAfterPositionalArgumentsMode (Qt 5.6) function
    // when available. Until then, options passed to sub-commands won't be
    // recognized by this parser.
    parser.parse(arguments);

    if (parser.positionalArguments().empty()) {
        if (parser.isSet("version")) {
            // Switch to parser.showVersion() when available (QT 5.4).
            out << KEEPASSXC_VERSION << Qt::endl;
            return EXIT_SUCCESS;
        } else if (parser.isSet(debugInfoOption)) {
            QString debugInfo = Tools::debugInfo().append("\n").append(Crypto::debugInfo());
            out << debugInfo << Qt::endl;
            return EXIT_SUCCESS;
        }
        // showHelp exits the application immediately.
        parser.showHelp();
    }

    const bool withFdoSecrets =
#ifdef WITH_XC_FDOSECRETS
        parser.isSet(Command::FdoSecretsOption)
#else
        false
#endif
        ;

    const bool withSSHAgent =
#ifdef WITH_XC_SSHAGENT
        parser.isSet(Command::SSHAgentOption)
#else
        false
#endif
        ;

    QString commandName = parser.positionalArguments().at(0);
    if (commandName == "open") {
        return enterInteractiveMode(app, arguments, withFdoSecrets, withSSHAgent);
    }

    auto command = Commands::getCommand(commandName);
    if (!command) {
        err << QObject::tr("Invalid command %1.").arg(commandName) << Qt::endl;
        err << parser.helpText();
        return EXIT_FAILURE;
    }

    // Removing the first argument (keepassxc).
    arguments.removeFirst();
    int exitCode = command->execute(arguments);

    if (command->currentDatabase) {
        command->currentDatabase.reset();
    }

#if defined(WITH_ASAN) && defined(WITH_LSAN)
    // do leak check here to prevent massive tail of end-of-process leak errors from third-party libraries
    __lsan_do_leak_check();
    __lsan_disable();
#endif

    return exitCode;
}
