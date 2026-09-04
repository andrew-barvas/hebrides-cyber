import { describe, it, expect } from "vitest";
import { parseGoModRequire, parsePomXmlDependencies } from "@/lib/scanners/dependencyManifest";

describe("parseGoModRequire", () => {
  it("parses a block-form require section, keeping indirect deps", () => {
    const raw = `module github.com/example/app

go 1.21

require (
	github.com/pkg/errors v0.9.1
	golang.org/x/net v0.17.0 // indirect
)
`;
    const deps = parseGoModRequire(raw);
    expect(deps).toEqual([
      { name: "github.com/pkg/errors", declaredRange: "github.com/pkg/errors v0.9.1", version: "0.9.1" },
      { name: "golang.org/x/net", declaredRange: "golang.org/x/net v0.17.0 // indirect", version: "0.17.0" },
    ]);
  });

  it("parses single-line require statements outside a block", () => {
    const raw = `module github.com/example/app\n\nrequire github.com/pkg/errors v0.9.1\n`;
    const deps = parseGoModRequire(raw);
    expect(deps).toEqual([
      { name: "github.com/pkg/errors", declaredRange: "github.com/pkg/errors v0.9.1", version: "0.9.1" },
    ]);
  });

  it("skips a pre-release/build-suffixed version rather than guessing at it", () => {
    const raw = `require (\n\tgithub.com/foo/bar v1.2.3-rc.1\n)\n`;
    expect(parseGoModRequire(raw)).toEqual([]);
  });

  it("ignores unrelated directives (module, go, replace) outside a require block", () => {
    const raw = `module github.com/example/app\ngo 1.21\nreplace github.com/old/pkg => github.com/new/pkg v1.0.0\n`;
    expect(parseGoModRequire(raw)).toEqual([]);
  });

  it("returns an empty array for a manifest with no require directives", () => {
    expect(parseGoModRequire("module github.com/example/app\n\ngo 1.21\n")).toEqual([]);
  });
});

describe("parsePomXmlDependencies", () => {
  it("extracts groupId:artifactId and a literal version", () => {
    const raw = `<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.9</version>
    </dependency>
  </dependencies>
</project>`;
    expect(parsePomXmlDependencies(raw)).toEqual([
      { name: "org.apache.commons:commons-lang3", declaredRange: "3.9", version: "3.9" },
    ]);
  });

  it("resolves a version referenced via a <properties> placeholder", () => {
    const raw = `<project>
  <properties>
    <lang3.version>3.12.0</lang3.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>\${lang3.version}</version>
    </dependency>
  </dependencies>
</project>`;
    expect(parsePomXmlDependencies(raw)).toEqual([
      { name: "org.apache.commons:commons-lang3", declaredRange: "${lang3.version}", version: "3.12.0" },
    ]);
  });

  it("skips a dependency whose property placeholder doesn't resolve", () => {
    const raw = `<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>\${undefined.version}</version>
    </dependency>
  </dependencies>
</project>`;
    expect(parsePomXmlDependencies(raw)).toEqual([]);
  });

  it("skips a non-literal version range rather than guessing", () => {
    const raw = `<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>[3.0,4.0)</version>
    </dependency>
  </dependencies>
</project>`;
    expect(parsePomXmlDependencies(raw)).toEqual([]);
  });

  it("ignores <dependencyManagement>'s own dependency entries", () => {
    const raw = `<project>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.apache.commons</groupId>
        <artifactId>commons-lang3</artifactId>
        <version>3.9</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>`;
    expect(parsePomXmlDependencies(raw)).toEqual([]);
  });

  it("finds only the real top-level dependency when both blocks are present", () => {
    // The realistic case: dependencyManagement pins a version, and the real
    // <dependencies> block (commonly appearing after it) is what's actually
    // built. A naive "first <dependencies> in the document" regex would
    // find dependencyManagement's nested one instead — this is the case
    // that guards against that.
    const raw = `<project>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>com.fasterxml.jackson</groupId>
        <artifactId>jackson-bom</artifactId>
        <version>2.15.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.9</version>
    </dependency>
  </dependencies>
</project>`;
    expect(parsePomXmlDependencies(raw)).toEqual([
      { name: "org.apache.commons:commons-lang3", declaredRange: "3.9", version: "3.9" },
    ]);
  });

  it("returns an empty array when there is no <dependencies> block at all", () => {
    expect(parsePomXmlDependencies("<project></project>")).toEqual([]);
  });

  it("skips an entry missing a groupId/artifactId/version", () => {
    const raw = `<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
    </dependency>
  </dependencies>
</project>`;
    expect(parsePomXmlDependencies(raw)).toEqual([]);
  });
});
