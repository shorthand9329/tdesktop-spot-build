/*
This file is part of Telegram Desktop,
the official desktop application for the Telegram messaging service.

For license and copyright information please follow this link:
https://github.com/telegramdesktop/tdesktop/blob/master/LEGAL
*/
#include "api/api_text_crypto.h"

#include "settings.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QDir>
#include <QtCore/QFile>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <gsl/gsl_util>
#include <cstring>

namespace Api::TextCrypto {
namespace {

constexpr auto kKeyFileName = "key.txt";
constexpr auto kPlainPrefix = "TGX1:";
constexpr auto kKeySize = 32;
constexpr auto kIvSize = 16;

struct KeyData {
	QByteArray bytes;
	QString error;
};

[[nodiscard]] QStringList KeyPaths() {
	auto result = QStringList();
	const auto add = [&](QString path) {
		if (!path.isEmpty() && !result.contains(path)) {
			result.push_back(std::move(path));
		}
	};
	add(QDir::current().absoluteFilePath(kKeyFileName));
	add(cWorkingDir() + kKeyFileName);
	add(QCoreApplication::applicationDirPath() + '/' + kKeyFileName);
	return result;
}

[[nodiscard]] KeyData ReadKey() {
	for (const auto &path : KeyPaths()) {
		auto file = QFile(path);
		if (!file.exists()) {
			continue;
		}
		if (!file.open(QIODevice::ReadOnly)) {
			return { {}, u"key.txt is not readable"_q };
		}
		const auto content = file.readAll();
		if (content.isEmpty()) {
			return { {}, u"key.txt is empty"_q };
		}
		auto digest = QByteArray(kKeySize, Qt::Uninitialized);
		SHA256(
			reinterpret_cast<const uchar*>(content.constData()),
			content.size(),
			reinterpret_cast<uchar*>(digest.data()));
		return { std::move(digest), QString() };
	}
	return { {}, u"key.txt not found"_q };
}

[[nodiscard]] const KeyData &Key() {
	static const auto result = ReadKey();
	return result;
}

[[nodiscard]] QByteArray Crypt(
		const QByteArray &input,
		const QByteArray &key,
		const QByteArray &iv,
		bool encrypt) {
	const auto cipher = EVP_aes_256_cbc();
	auto context = EVP_CIPHER_CTX_new();
	if (!context) {
		return {};
	}
	const auto guard = gsl::finally([&] {
		EVP_CIPHER_CTX_free(context);
	});
	const auto init = encrypt
		? EVP_EncryptInit_ex(
			context,
			cipher,
			nullptr,
			reinterpret_cast<const uchar*>(key.constData()),
			reinterpret_cast<const uchar*>(iv.constData()))
		: EVP_DecryptInit_ex(
			context,
			cipher,
			nullptr,
			reinterpret_cast<const uchar*>(key.constData()),
			reinterpret_cast<const uchar*>(iv.constData()));
	if (init != 1) {
		return {};
	}
	auto output = QByteArray(input.size() + EVP_CIPHER_block_size(cipher), 0);
	auto out = 0;
	auto total = 0;
	const auto update = encrypt
		? EVP_EncryptUpdate(
			context,
			reinterpret_cast<uchar*>(output.data()),
			&out,
			reinterpret_cast<const uchar*>(input.constData()),
			input.size())
		: EVP_DecryptUpdate(
			context,
			reinterpret_cast<uchar*>(output.data()),
			&out,
			reinterpret_cast<const uchar*>(input.constData()),
			input.size());
	if (update != 1) {
		return {};
	}
	total += out;
	const auto final = encrypt
		? EVP_EncryptFinal_ex(
			context,
			reinterpret_cast<uchar*>(output.data()) + total,
			&out)
		: EVP_DecryptFinal_ex(
			context,
			reinterpret_cast<uchar*>(output.data()) + total,
			&out);
	if (final != 1) {
		return {};
	}
	total += out;
	output.resize(total);
	return output;
}

[[nodiscard]] bool LooksEncrypted(const QString &text) {
	const auto decoded = QByteArray::fromBase64(text.toUtf8());
	return decoded.size() > kIvSize && ((decoded.size() - kIvSize) % kIvSize == 0);
}

} // namespace

QString EncryptForSending(const QString &text) {
	if (text.isEmpty() || LooksEncrypted(text)) {
		return text;
	}
	const auto &key = Key();
	if (key.bytes.size() != kKeySize) {
		LOG(("TextCrypto Error: %1").arg(key.error));
		return QString();
	}
	auto iv = QByteArray(kIvSize, Qt::Uninitialized);
	if (RAND_bytes(reinterpret_cast<uchar*>(iv.data()), iv.size()) != 1) {
		LOG(("TextCrypto Error: could not generate IV."));
		return QString();
	}
	const auto plain = QByteArray(kPlainPrefix) + text.toUtf8();
	const auto encrypted = Crypt(plain, key.bytes, iv, true);
	if (encrypted.isEmpty()) {
		LOG(("TextCrypto Error: encryption failed."));
		return QString();
	}
	return QString::fromLatin1((iv + encrypted).toBase64());
}

QString DecryptForDisplay(const QString &text) {
	if (text.isEmpty()) {
		return text;
	}
	const auto decoded = QByteArray::fromBase64(text.toUtf8());
	if (decoded.size() <= kIvSize) {
		return text;
	}
	const auto &key = Key();
	if (key.bytes.size() != kKeySize) {
		return text;
	}
	const auto iv = decoded.mid(0, kIvSize);
	const auto encrypted = decoded.mid(kIvSize);
	const auto plain = Crypt(encrypted, key.bytes, iv, false);
	if (!plain.startsWith(kPlainPrefix)) {
		return text;
	}
	return QString::fromUtf8(plain.mid(int(strlen(kPlainPrefix))));
}

} // namespace Api::TextCrypto
