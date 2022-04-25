{ mkShell, sage }:

let
  sage' = sage.override {
    requireSageTests = false;
    extraPythonPackages = p: with p; [
      bitstring
      pycryptodome
      pwntools
    ];
  };
in
mkShell {
  buildInputs = [
    sage'
  ];
}
