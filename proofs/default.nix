with import <nixpkgs> { };

stdenv.mkDerivation rec {
  name = "env";
	
  nativeBuildInputs = [
    python3
    tamarin-prover
  ];
}

