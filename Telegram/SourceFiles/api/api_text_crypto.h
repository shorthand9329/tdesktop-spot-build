/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QString>

namespace Api::TextCrypto {

[[nodiscard]] QString EncryptForSending(const QString &text);
[[nodiscard]] QString DecryptForDisplay(const QString &text);

} // namespace Api::TextCrypto
