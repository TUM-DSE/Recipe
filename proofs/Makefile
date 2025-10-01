default: all

all: proofs/recipe_protocols_analyzed.spthy

proofs/recipe_protocols_analyzed.spthy: recipe_protocols.spthy 
	tamarin-prover --prove recipe_protocols.spthy -o=proofs/recipe_protocols_analyzed.spthy > proofs/recipe_protocols_summary.txt

proofs/sanity_complete_attestation_phase.spthy: recipe_protocols.spthy 
	tamarin-prover --prove=sanity_complete_attestation_phase recipe_protocols.spthy -o=proofs/sanity_complete_attestation_phase.spthy > proofs/sanity_complete_attestation_phase_summary.txt
 
proofs/sanity_complete_accept_message.spthy: recipe_protocols.spthy 
	tamarin-prover --prove=sanity_complete_accept_message recipe_protocols.spthy -o=proofs/sanity_complete_accept_message.spthy > proofs/sanity_complete_accept_message_summary.txt

proofs/verified_msg_is_auth.spthy: recipe_protocols.spthy 
	tamarin-prover --prove=verified_msg_is_auth recipe_protocols.spthy -o=proofs/verified_msg_is_auth.spthy > proofs/verified_msg_is_auth_summary.txt

proofs/no_lost_messages.spthy: recipe_protocols.spthy 
	tamarin-prover --prove=no_lost_messages recipe_protocols.spthy -o=proofs/no_lost_messages.spthy > proofs/no_lost_messages_summary.txt

proofs/no_message_reordering.spthy: recipe_protocols.spthy 
	tamarin-prover --prove=no_message_reordering recipe_protocols.spthy -o=proofs/no_message_reordering.spthy > proofs/no_message_reordering_summary.txt

proofs/no_double_messages.spthy: recipe_protocols.spthy 
	tamarin-prover --prove=no_double_messages recipe_protocols.spthy -o=proofs/no_double_messages.spthy > proofs/no_double_messages_summary.txt