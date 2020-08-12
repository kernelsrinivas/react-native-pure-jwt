export interface DecodeResponse {
    headers: object;
    payload: object;
}

export interface SignOptions {
    alg: "HS256" | "HS384" | "HS512" | "RS256" | "RS384" | "RS512";
}

export interface DecodeOptions extends SignOptions {
    skipValidation?: boolean;
}

export interface KeyPair {
    privateKey: string;
    publicKey: string;
}

interface RNPureJwt {
    generateRSAKeys: (keySize: number) => Promise<KeyPair>;
    sign: (payload: object, secret: string, options: SignOptions) => Promise<string>;
    decode: (token: string, secret: string, options: DecodeOptions) => Promise<DecodeResponse>;
}

export default RNPureJwt;
