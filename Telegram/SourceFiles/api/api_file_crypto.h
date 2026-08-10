/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#pragma once

#include <QtCore/QByteArray>
#include <QtCore/QString>

#include <optional>

namespace Api::FileCrypto {

struct DecryptedFile {
	QString filename;
	QString mime;
	QByteArray content;
};

[[nodiscard]] QByteArray EncryptPackage(
	const QByteArray &content,
	const QString &filename,
	const QString &mime);
[[nodiscard]] std::optional<DecryptedFile> DecryptPackage(
	const QByteArray &content);

} // namespace Api::FileCrypto
