import {IBackboneHandler, ILatency} from "./baseTypes";
import {BackboneContext, LatencyRecord} from "./baseTypes";
//import forge from 'node-forge';
import jwt from 'jsonwebtoken';
import { OAGError } from "./errors";
import { SecretsManagerClient, GetSecretValueCommand, PutSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import fs from 'fs';

export class TokenHandler implements IBackboneHandler, ILatency {

    public process(backboneContext: BackboneContext): void {

        let tokenPayload = backboneContext.tokenPayload;
        if (tokenPayload == null) {
            throw new OAGError('Invalid token', 'ATH02', 401);
        }

        tokenPayload['iss'] = 'provider.ehealthontario.ca';
        if( backboneContext.apiSetup.signTokenRequired ) {
            
            const alg = 'RS256';
            const header = {
                alg: alg,
                type: 'JWT',
                kid: backboneContext.backboneSetting.signingKid
            }

            const now = Math.floor(Date.now() / 1000); 
            tokenPayload['nbf'] = now - 300; 
            tokenPayload['exp'] = now + 3600 + 300;     

            const lobToken = jwt.sign(tokenPayload, backboneContext.backboneSetting.privateSigningKey, {
                algorithm: alg, 
                header: header 
              });

            // const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
            // const encodedPayload = this.base64UrlEncode(JSON.stringify(tokenPayload));        
            // const signature = this.sign(encodedHeader + '.' + encodedPayload, backboneContext.backboneSetting.privateSigningKey);
            // let lobToken = `${encodedHeader}.${encodedPayload}.${signature}`;


            backboneContext.lobExtraHeaders['Authorization'] = `Bearer ${lobToken}`;

            fs.writeFileSync('token.txt', lobToken);
        }
        else {
           const lobToken = JSON.stringify( tokenPayload );
           backboneContext.lobExtraHeaders['Authorization'] = `Bearer ${lobToken}`;
        }

        console.log('extra lob headers: ' + JSON.stringify(backboneContext.lobExtraHeaders));
    }

    public recordLatency(backboneContext: BackboneContext): void {

    }

    // private sign(input: string, privateKeyPem: string): string {
    //     const md = forge.md.sha256.create();
    //     md.update(input, 'utf8');    
    //     const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
    //     const signature = privateKey.sign(md);    
    //     //return this.base64UrlEncode(forge.util.encode64(signature));
    //     return this.base64UrlEncode(signature);
    // }

    // private base64UrlEncode(str: string): string {
    //     return Buffer.from(str).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    // }
}
