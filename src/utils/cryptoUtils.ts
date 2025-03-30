import crypto from 'crypto';
import { promisify } from 'util';

export interface CryptoOptions {
    saltRounds?: number;
    keyLength?: number;
    algorithm?: string;
    hashAlgorithm?: string;
    secretKey?: string | Buffer;
}

export interface HashResult {
    hash: string;
    salt: string;
}

export interface EncryptedData {
    encrypted: string;
    iv: string;
    authTag: string;
}

export class CryptoUtils {
    private options: Required<CryptoOptions>;
    private secretKey: Buffer;

    constructor(options: CryptoOptions = {}) {
        this.options = {
            saltRounds: 10,
            keyLength: 32,
            algorithm: 'aes-256-gcm',
            hashAlgorithm: 'sha512',
            secretKey: options.secretKey || crypto.randomBytes(32),
            ...options
        };

        this.secretKey = Buffer.isBuffer(this.options.secretKey)
            ? this.options.secretKey
            : Buffer.from(this.options.secretKey);
    }

    async hashPassword(password: string): Promise<HashResult> {
        const salt = crypto.randomBytes(16);
        const hash = await promisify(crypto.pbkdf2)(
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

    async verifyPassword(password: string, hash: string, salt: string): Promise<boolean> {
        const verifyHash = await promisify(crypto.pbkdf2)(
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

    encrypt(data: string | object): EncryptedData {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv(
            this.options.algorithm,
            this.secretKey,
            iv
        ) as crypto.CipherGCM;

        const stringData = typeof data === 'string' ? data : JSON.stringify(data);
        
        let encrypted = cipher.update(stringData, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        return {
            encrypted,
            iv: iv.toString('hex'),
            authTag: cipher.getAuthTag().toString('hex')
        };
    }

    decrypt(encryptedData: EncryptedData): string {
        const decipher = crypto.createDecipheriv(
            this.options.algorithm,
            this.secretKey,
            Buffer.from(encryptedData.iv, 'hex')
        ) as crypto.DecipherGCM;

        decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));

        let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        try {
            return JSON.parse(decrypted);
        } catch {
            return decrypted;
        }
    }

    generateToken(length: number = 32): string {
        return crypto.randomBytes(length).toString('hex');
    }

    hash(data: string): string {
        return crypto
            .createHash(this.options.hashAlgorithm)
            .update(data)
            .digest('hex');
    }

    hmac(data: string, key: string | Buffer = this.secretKey): string {
        return crypto
            .createHmac(this.options.hashAlgorithm, key)
            .update(data)
            .digest('hex');
    }
} 