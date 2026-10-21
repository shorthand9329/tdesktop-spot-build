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

[[nodiscard]] std::optional<DecryptedFile> ParseSerialized(
		const QByteArray &plain) {
	if (plain.isEmpty()) {
		return std::nullopt;
	}
	auto result = DecryptedFile();
	auto stream = QDataStream(plain);
	stream.setVersion(QDataStream::Qt_5_15);
	stream >> result.filename >> result.mime >> result.content;
	if (stream.status() != QDataStream::Ok || result.content.isEmpty()) {
		return std::nullopt;
	}
	return result;
}

[[nodiscard]] std::optional<DecryptedFile> ParseLengthsPackage(
		const QByteArray &plain) {
	// WHY: another build stores a header with the name and the type and then
	// the raw content, each behind a big endian byte count.
	if (plain.size() < 12) {
		return std::nullopt;
	}
	auto offset = 0;
	const auto readLength = [&]() -> int {
		if (offset + 4 > plain.size()) {
			return -1;
		}
		const auto raw = plain.mid(offset, 4);
		auto stream = QDataStream(raw);
		auto value = quint32(0);
		stream >> value;
		offset += 4;
		return (stream.status() == QDataStream::Ok
			&& value <= quint32(plain.size()))
			? int(value)
			: -1;
	};
	const auto headerLength = readLength();
	if (headerLength <= 0 || offset + headerLength > plain.size()) {
		return std::nullopt;
	}
	const auto header = plain.mid(offset, headerLength);
	offset += headerLength;
	const auto contentLength = readLength();
	if (contentLength <= 0 || offset + contentLength != plain.size()) {
		return std::nullopt;
	}
	auto result = DecryptedFile();
	result.content = plain.mid(offset, contentLength);

	// The header holds two UTF-16 strings, a two code unit byte count in front
	// of each of them: the file name and then the mime type.
	auto text = QString();
	text.reserve(header.size() / 2);
	for (auto i = 0; i != int(header.size() / 2); ++i) {
		text.append(QChar(ushort(
			(ushort(uchar(header[2 * i])) << 8)
			| ushort(uchar(header[2 * i + 1])))));
	}
	auto position = 0;
	const auto readField = [&]() -> QString {
		if (position + 2 > text.size()) {
			return {};
		}
		const auto bytes = (text.at(position).unicode() << 8)
			| text.at(position + 1).unicode();
		position += 2;
		const auto count = int(bytes) / 2;
		if (count <= 0 || position + count > text.size()) {
			position = text.size();
			return {};
		}
		const auto field = text.mid(position, count);
		position += count;
		return field;
	};
	result.filename = readField();
	result.mime = readField();
	if (position != text.size()) {
		result.filename = QString();
		result.mime = QString();
	}
	return result;
}

[[nodiscard]] std::optional<DecryptedFile> ParsePayload(
		const QByteArray &payload) {
	// This build's container serializes an encrypted QString: a big endian
	// byte count followed by UTF-16. Only read it when that count is plausible,
	// otherwise a raw container below would be misread as a huge string.
	auto stringLength = quint32(0);
	auto probe = QDataStream(payload);
	probe.setVersion(QDataStream::Qt_5_15);
	probe >> stringLength;
	if (probe.status() == QDataStream::Ok
		&& stringLength > 0
		&& (stringLength % 2) == 0
		&& qint64(stringLength) + 4 <= payload.size()) {
		auto encrypted = QString();
		auto stream = QDataStream(payload);
		stream.setVersion(QDataStream::Qt_5_15);
		stream >> encrypted;
		if (!encrypted.isEmpty()) {
			if (const auto parsed = ParseSerialized(DecryptBytes(encrypted))) {
				return parsed;
			}
			// WHY: older packages were written before the payload was really
			// encrypted, so the container holds the plain base64 of the data.
			if (const auto parsed = ParseSerialized(
					QByteArray::fromBase64(encrypted.toUtf8()))) {
				return parsed;
			}
		}
	}
	// WHY: other builds wrote the iv and the ciphertext straight into the
	// container, without any serialized string around them.
	const auto plain = TextCrypto::DecryptRaw(payload);
	if (plain.isEmpty()) {
		return std::nullopt;
	}
	if (const auto parsed = ParseSerialized(plain)) {
		return parsed;
	}
	if (const auto parsed = ParseSerialized(QByteArray::fromBase64(plain))) {
		return parsed;
	}
	if (const auto parsed = ParseLengthsPackage(plain)) {
		return parsed;
	}
	// The payload decrypted cleanly, so take it as the content itself.
	return DecryptedFile{ .content = plain };
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
	return ParsePayload(content.mid(int(strlen(kMagic))));
}

} // namespace Api::FileCrypto
