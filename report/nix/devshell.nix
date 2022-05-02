{
  go-task,
  latexrun,
  mkShell,
  texlive,
}:
mkShell {
  buildInputs = [
    go-task
    latexrun
    texlive.combined.scheme-full
  ];
}
