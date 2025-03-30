import sqlstring from 'sqlstring';
import DOMPurify from 'isomorphic-dompurify';
import sanitizeHtml from 'sanitize-html';

export interface SanitizerOptions {
    htmlAllowed?: boolean;
    allowedTags?: string[];
    allowedAttributes?: { [key: string]: string[] };
    maxLength?: number;
    stripSpecialChars?: boolean;
}

export class InputSanitizer {
    private options: Required<SanitizerOptions>;

    constructor(options: SanitizerOptions = {}) {
        this.options = {
            htmlAllowed: false,
            allowedTags: ['b', 'i', 'em', 'strong', 'a'],
            allowedAttributes: {
                'a': ['href', 'title']
            },
            maxLength: 1000,
            stripSpecialChars: true,
            ...options
        };
    }

    sanitize(input: any): string {
        if (input === null || input === undefined) {
            return '';
        }

        let sanitized = this.convertToString(input);

        // Truncate if needed
        if (this.options.maxLength > 0) {
            sanitized = sanitized.substring(0, this.options.maxLength);
        }

        // Strip special characters if enabled
        if (this.options.stripSpecialChars) {
            sanitized = this.stripSpecialCharacters(sanitized);
        }

        // Handle HTML content
        if (this.options.htmlAllowed) {
            sanitized = this.sanitizeHTML(sanitized);
        } else {
            sanitized = this.escapeHTML(sanitized);
        }

        return sanitized;
    }

    sanitizeForSQL(input: string): string {
        return sqlstring.escape(input);
    }

    sanitizeHTML(input: string): string {
        // First pass with DOMPurify
        let sanitized = DOMPurify.sanitize(input, {
            ALLOWED_TAGS: this.options.allowedTags,
            ALLOWED_ATTR: Object.entries(this.options.allowedAttributes)
                .flatMap(([_, attrs]) => attrs)
        });

        // Second pass with sanitize-html for more granular control
        sanitized = sanitizeHtml(sanitized, {
            allowedTags: this.options.allowedTags,
            allowedAttributes: this.options.allowedAttributes
        });

        return sanitized;
    }

    private convertToString(input: any): string {
        if (typeof input === 'string') return input;
        if (typeof input === 'number') return input.toString();
        if (typeof input === 'boolean') return input.toString();
        if (Array.isArray(input)) return input.join(', ');
        if (typeof input === 'object') return JSON.stringify(input);
        return String(input);
    }

    private escapeHTML(input: string): string {
        return input
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    private stripSpecialCharacters(input: string): string {
        return input
            .replace(/[^\w\s-.,]/g, '')
            .replace(/\s+/g, ' ')
            .trim();
    }
}

export default InputSanitizer; 