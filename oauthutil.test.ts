import { describe, it, expect } from 'vitest';
import { buildURI } from './oauthutil';

describe('Uri builder', () => {
    it('should return just the original url when given empty params object', () => {
        let res = buildURI('http://test.com', {});
        expect(res).toEqual('http://test.com');
    })

    it('should return correct uri when provided params', () => {
        let res = buildURI('http://test.com', {a: '1', b: '2', c: '3'});
        expect(res).toEqual('http://test.com?a=1&b=2&c=3');
    })

    it('should return correct uri when base uri already has params', () => {
        let res = buildURI('http://test.com?a=1', {b: '2', c: '3'});
        expect(res).toEqual('http://test.com?a=1&b=2&c=3');
    })
})