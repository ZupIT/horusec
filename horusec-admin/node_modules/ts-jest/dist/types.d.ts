import type * as _babel from 'babel__core';
import type * as _ts from 'typescript';
export declare type TTypeScript = typeof _ts;
export declare type BabelConfig = _babel.TransformOptions;
export interface AstTransformer<T = Record<string, unknown>> {
    path: string;
    options?: T;
}
export interface ConfigCustomTransformer {
    before?: (string | AstTransformer)[];
    after?: (string | AstTransformer)[];
    afterDeclarations?: (string | AstTransformer)[];
}
export interface TsJestGlobalOptions {
    tsConfig?: boolean | string | _ts.CompilerOptions;
    tsconfig?: boolean | string | _ts.CompilerOptions;
    packageJson?: boolean | string | Record<string, unknown>;
    isolatedModules?: boolean;
    compiler?: string;
    astTransformers?: string[] | ConfigCustomTransformer;
    diagnostics?: boolean | {
        pretty?: boolean;
        ignoreCodes?: number | string | (number | string)[];
        pathRegex?: RegExp | string;
        warnOnly?: boolean;
    };
    babelConfig?: boolean | string | BabelConfig;
    stringifyContentPathRegex?: string | RegExp;
}
export interface TsJestDiagnosticsCfg {
    pretty: boolean;
    ignoreCodes: number[];
    pathRegex?: string | undefined;
    throws: boolean;
    warnOnly?: boolean;
}
export interface TsCompiler {
    program: _ts.Program | undefined;
}
