/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "api/api_file_crypto.h"

#include "api/api_text_crypto.h"

#include <QtCore/QBuffer>
#include <QtCore/QDataStream>

#include <cstring>

namespace Api::FileCrypto {
namespace {

constexpr auto kMagic = "TGXF1";

[[nodiscard]] QString EncryptBytes(const QByteArray &bytes) {
	return TextCrypto::EncryptForSending(QString::fromUtf8(bytes.toBase64()));
}

[[nodiscard]] QByteArray DecryptBytes(const QString &text) {
	const auto decrypted = TextCrypto::DecryptForDisplay(text);
	if (decrypted == text) {
		return {};
	}
	return QByteArray::fromBase64(decrypted.toUtf8());
}

} // namespace

QByteArray EncryptPackage(
		const QByteArray &content,
		const QString &filename,
		const QString &mime) {
	if (content.startsWith(kMagic)) {
		return content;
	}
	auto plain = QByteArray();
	{
		auto stream = QDataStream(&plain, QIODevice::WriteOnly);
		stream.setVersion(QDataStream::Qt_5_15);
		stream << filename << mime << content;
	}
	const auto encrypted = EncryptBytes(plain);
	if (encrypted.isEmpty()) {
		return {};
	}
	auto result = QByteArray(kMagic);
	auto stream = QDataStream(&result, QIODevice::Append);
	stream.setVersion(QDataStream::Qt_5_15);
	stream << encrypted;
	return result;
}

std::optional<DecryptedFile> DecryptPackage(const QByteArray &content) {
	if (!content.startsWith(kMagic)) {
		return std::nullopt;
	}
	auto package = content.mid(int(strlen(kMagic)));
	auto encrypted = QString();
	{
		auto stream = QDataStream(package);
		stream.setVersion(QDataStream::Qt_5_15);
		stream >> encrypted;
	}
	const auto plain = DecryptBytes(encrypted);
	if (plain.isEmpty()) {
		return std::nullopt;
	}
	auto result = DecryptedFile();
	{
		auto stream = QDataStream(plain);
		stream.setVersion(QDataStream::Qt_5_15);
		stream >> result.filename >> result.mime >> result.content;
	}
	if (result.content.isEmpty()) {
		return std::nullopt;
	}
	return result;
}

} // namespace Api::FileCrypto
