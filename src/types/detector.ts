export interface SecurityThreat {
    type: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH';
    description: string;
    location?: string;
    value?: string;
}

export interface DetectorOptions {
    customRules?: RegExp[];
    sensitivity?: 'LOW' | 'MEDIUM' | 'HIGH';
    maxLength?: number;
    allowedPatterns?: RegExp[];
    blocklistPatterns?: RegExp[];
}

export interface DetectedPayload {
    type: string;
    value: string;
    pattern?: RegExp;
    confidence: number;
}

export interface QueryObject {
    [key: string]: string | number | boolean | null | undefined | QueryObject | Array<unknown>;
} 