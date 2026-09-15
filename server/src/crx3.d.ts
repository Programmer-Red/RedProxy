declare module 'crx3' {
  export interface Crx3Options {
    keyPath?: string;
    crxPath?: string;
    zipPath?: string;
    xmlPath?: string;
    srcPaths?: string[];
    appVersion?: string;
    crxURL?: string;
    browserVersion?: string;
    forceDateTime?: number;
  }

  function crx3(files: string[] | NodeJS.ReadableStream, options?: Crx3Options): Promise<unknown>;
  export = crx3;
}
