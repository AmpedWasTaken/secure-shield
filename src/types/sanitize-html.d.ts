declare module 'sanitize-html' {
    interface IOptions {
        allowedTags?: string[];
        allowedAttributes?: { [key: string]: string[] };
        allowedIframeHostnames?: string[];
        allowedStyles?: { [key: string]: { [key: string]: RegExp[] } };
        allowedClasses?: { [key: string]: string[] };
        allowedSchemes?: string[];
        allowProtocolRelative?: boolean;
        selfClosing?: string[];
        allowedScriptHostnames?: string[];
        allowedScriptDomains?: string[];
        allowVulnerableTags?: boolean;
        parseStyleAttributes?: boolean;
    }

    function sanitize(dirty: string, options?: IOptions): string;
    
    export = sanitize;
} 