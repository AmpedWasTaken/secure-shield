const crypto = require('crypto');
const util = require('util');

class CryptoUtils {
    constructor(options = {}) {
        this.options = {
            saltRounds: 10,
            keyLength: 32,
            algorithm: 'aes-256-gcm',
            hashAlgorithm: 'sha512',
            ...options
        };

        this.secretKey = options.secretKey || crypto.randomBytes(32);
    }

    async hashPassword(password) {
        const salt = crypto.randomBytes(16);
        const hash = await util.promisify(crypto.pbkdf2)(
            password,
            salt,
            100000,
            this.options.keyLength,
            this.options.hashAlgorithm
        );

        return {
            hash: hash.toString('hex'),
            salt: salt.toString('hex')
        };
    }

    async verifyPassword(password, hash, salt) {
        const verifyHash = await util.promisify(crypto.pbkdf2)(
            password,
            Buffer.from(salt, 'hex'),
            100000,
            this.options.keyLength,
            this.options.hashAlgorithm
        );

        return crypto.timingSafeEqual(
            Buffer.from(hash, 'hex'),
            verifyHash
        );
    }

    encrypt(data) {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv(
            this.options.algorithm,
            this.secretKey,
            iv
        );

        let encrypted = cipher.update(
            typeof data === 'string' ? data : JSON.stringify(data),
            'utf8',
            'hex'
        );
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag();

        return {
            encrypted,
            iv: iv.toString('hex'),
            authTag: authTag.toString('hex')
        };
    }

    decrypt(encryptedData) {
        const decipher = crypto.createDecipheriv(
            this.options.algorithm,
            this.secretKey,
            Buffer.from(encryptedData.iv, 'hex')
        );

        decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));

        let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        try {
            return JSON.parse(decrypted);
        } catch {
            return decrypted;
        }
    }

    generateToken(length = 32) {
        return crypto.randomBytes(length).toString('hex');
    }

    hash(data) {
        return crypto
            .createHash(this.options.hashAlgorithm)
            .update(data)
            .digest('hex');
    }

    hmac(data, key = this.secretKey) {
        return crypto
            .createHmac(this.options.hashAlgorithm, key)
            .update(data)
            .digest('hex');
    }
}

module.exports = CryptoUtils; 