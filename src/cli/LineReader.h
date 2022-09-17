/*
 *  Copyright (C) 2022 KeePassXC Team <team@keepassxc.org>
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

#ifndef KEEPASSXC_LINEREADER_H
#define KEEPASSXC_LINEREADER_H

#include <QSocketNotifier>

#include "TextStream.h"
#include "Utils.h"

#if defined(USE_READLINE)
#include <readline/history.h>
#include <readline/readline.h>
#endif

class LineReader : public QObject
{
    Q_OBJECT

    friend class LineReaderGuard;

public:
    LineReader(const QString& prompt)
        : m_prompt{prompt}
        , m_notifier{fileno(stdin), QSocketNotifier::Read}
    {
    }

    ~LineReader() override
    {
        m_notifier.disconnect(this);
    }

signals:
    void readLine(const QString command);
    void finished();

private:
    virtual void pause() = 0;
    virtual void restore() = 0;

protected:
    // We keep reference so it can be updated externally in signal handler
    const QString& m_prompt;
    QSocketNotifier m_notifier;
};

class LineReaderGuard
{
public:
    LineReaderGuard(LineReader* lineReader)
        : m_lineReader(lineReader)
    {
        Q_ASSERT(m_lineReader);
        m_lineReader->pause();
    }

    ~LineReaderGuard()
    {
        Q_ASSERT(m_lineReader);
        m_lineReader->restore();
    }

private:
    LineReader* m_lineReader;
};

class SimpleLineReader : public LineReader
{
    Q_OBJECT

public:
    SimpleLineReader(const QString& prompt)
        : LineReader(prompt)
        , m_input(stdin, QIODevice::ReadOnly)
        , m_output(stdout, QIODevice::WriteOnly)
    {
        restore();
    }

    ~SimpleLineReader() override = default;

private:
    void pause() override
    {
        m_output << Qt::endl;
        m_notifier.disconnect(this);
    }

    void restore() override
    {
        m_output << m_prompt;
        m_output.flush();
        connect(&m_notifier, &QSocketNotifier::activated, [this]() {
            if (m_input.atEnd()) {
                m_notifier.disconnect(this);
                emit finished();
                return;
            }

            QString current = m_input.readLine();
            emit readLine(current);

            m_output << m_prompt;
            m_output.flush();
        });
    }

private:
    TextStream m_input;
    TextStream m_output;
};

#if defined(USE_READLINE)
class ReadlineLineReader : public LineReader
{
    Q_OBJECT

public:
    ReadlineLineReader(const QString& prompt)
        : LineReader(prompt)
    {
        // Readline handlers are plain C functions, need to keep the instance somewhere available
        Q_ASSERT(instance == nullptr);
        instance = this;
        restore();
    }

    ~ReadlineLineReader() override
    {
        // Remove readline handler at the end
        // This restores original terminal settings
        rl_callback_handler_remove();
    }

    static void s_readLine(char* line)
    {
        Q_ASSERT(instance);
        instance->handleLine(line);
        add_history(line);
        free(line);
    }

    void handleLine(const QString& line)
    {
        // Remove handler early, we will reinstate it after the line has been processed
        // This restores original terminal settings
        rl_callback_handler_remove();
        if (line.isNull()) {
            m_notifier.disconnect(this);
            emit finished();
            return;
        }

        emit readLine(line);

        auto c_prompt = m_prompt.toLatin1();
        rl_callback_handler_install(c_prompt.data(), s_readLine);
    }

private:
    void pause() override
    {
        m_notifier.disconnect(this);
        rl_callback_handler_remove();
    }

    void restore() override
    {
        auto c_prompt = m_prompt.toLatin1();
        // This will also switch terminal settings needed by readline (no buffering)
        rl_callback_handler_install(c_prompt.data(), s_readLine);
        // Without buffering we get readiness after each input char, just let readline read it
        connect(&m_notifier, &QSocketNotifier::activated, rl_callback_read_char);
    }

private:
    inline static ReadlineLineReader* instance = nullptr;
};
#endif

#endif // KEEPASSXC_LINEREADER_H
