/**
 * Minimal script to generate a User Configuration Merkle Tree (UCMT) and verify
 * its root and proofs.
 *
 * By design, the Keystore holds only the Merkle tree root hash onchain while the
 * actual configuration is stored offchain. Consequently, all stakeholders of an
 * account MUST have access to the UCMT in order to verify that the onchain root
 * hash exactly matches the expected configuration. This prevents a bad actor from
 * attempting to hide a malicious configuration within the Merkle tree.
 */
import { SimpleMerkleTree } from "@openzeppelin/merkle-tree";
import { AbiParameters, Hash } from "ox";

/**
 * An example UCMT stored as an array of nodes. Each node is a tuple of the verifier
 * address and the node configuration. When building the Merkle tree, each node is
 * packed and hashed using `keccak256`.
 */
const USER_CONFIGURATION_MERKLE_TREE = [
  ["0x000000000000000000000000000000000000dEaD", "0xdeadbeef"],
  ["0x000000000000000000000000000000000000bEEF", "0x"],
  ["0x000000000000000000000000000000000000cafE", "0x0000000ff1ce"],
  ["0x000000000000000000000000000000000000F00D", "0xc0ffee"],
] as const;

function main() {
  const merkleTree = SimpleMerkleTree.of(
    USER_CONFIGURATION_MERKLE_TREE.map((node) =>
      Hash.keccak256(AbiParameters.encodePacked(["address", "bytes"], node))
    )
  );

  console.log("UCMT:", USER_CONFIGURATION_MERKLE_TREE);
  console.log("UCMT root:", merkleTree.root);
  console.log("UCMT proofs...");
  USER_CONFIGURATION_MERKLE_TREE.forEach((_, i) =>
    console.log(`node ${i + 1}:`, merkleTree.getProof(i))
  );

  console.log(
    "\nVerify different configurations by changing the merkle tree in examples/verify-ucmt.ts."
  );
  console.log(
    "Always check that your UCMT aligns with your account's onchain root hash."
  );
}

main();
