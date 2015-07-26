/// <reference path="..\..\main\ts\sha1.ts" />

declare var describe: { (description: string, content: Function): void };
declare var it: { (description: string, content: Function): void };

declare var require: { (moduleName: string): any };
var assert = require("assert");

describe('Function call `hex_sha1("abc")`', () => {
    it('should return the text "a9993e364706816aba3e25717850c26c9cd0d89d"', () => {
        assert.equal(hex_sha1("abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
    });
});
