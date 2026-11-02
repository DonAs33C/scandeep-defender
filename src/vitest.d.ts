/// <reference types="vitest/globals" />

import type {
  VitestUtils,
  Mock,
  MockInstance,
  Mocked,
  MockedClass,
  MockedFunction,
  MockedObject,
  MockContext,
  MockOptions,
  MockFactoryWithHelper,
  MaybeMocked,
  MaybeMockedDeep,
  MaybePartiallyMocked,
  MaybePartiallyMockedDeep
} from "vitest";

declare module "vitest" {
  // Value exports
  export const vi: VitestUtils;
  export const vitest: VitestUtils;
  export const beforeAll: VitestUtils["beforeAll"];
  export const afterAll: VitestUtils["afterAll"];
  export const beforeEach: VitestUtils["beforeEach"];
  export const afterEach: VitestUtils["afterEach"];
  export const describe: VitestUtils["describe"];
  export const it: VitestUtils["it"];
  export const test: VitestUtils["test"];
  export const expect: VitestUtils["expect"];
  export const suite: VitestUtils["suite"];

  // Type exports
  export type {
    Mock,
    MockInstance,
    Mocked,
    MockedClass,
    MockedFunction,
    MockedObject,
    MockContext,
    MockOptions,
    MockFactoryWithHelper,
    MaybeMocked,
    MaybeMockedDeep,
    MaybePartiallyMocked,
    MaybePartiallyMockedDeep,
    VitestUtils
  };

  // Allow vi to be used as namespace for types (declaration merging with const vi)
  export namespace vi {
    export type Mock = Mock;
    export type MockInstance = MockInstance;
    export type Mocked = Mocked;
    export type MockedClass = MockedClass;
    export type MockedFunction = MockedFunction;
    export type MockedObject = MockedObject;
    export type MockContext = MockContext;
    export type MockOptions = MockOptions;
    export type MockFactoryWithHelper = MockFactoryWithHelper;
    export type MaybeMocked = MaybeMocked;
    export type MaybeMockedDeep = MaybeMockedDeep;
    export type MaybePartiallyMocked = MaybePartiallyMocked;
    export type MaybePartiallyMockedDeep = MaybePartiallyMockedDeep;
  }
}

// Also declare global vi namespace for when globals are used without import
declare global {
  namespace vi {
    export type Mock = Mock;
    export type MockInstance = MockInstance;
    export type Mocked = Mocked;
    export type MockedClass = MockedClass;
    export type MockedFunction = MockedFunction;
    export type MockedObject = MockedObject;
  }
}