Phase 1: Rule-Based Training Success

Successfully completed Phase 1 of training a Deep Q-Network (DQN) using StableBaselines3 within the MiniCage environment for intrusion detection.
The trained agent currently evaluates incoming test vectors and classifies them as either attacks or benign, based on rule-based behavioral patterns.

Custom Logging Implemented: Built robust logging to track decisions, rewards, and edge case behavior.

Reward Function Modification: Designed a customized reward function with strong penalization for incorrect classifications, enforcing precise learning dynamics.

Edge Case Verification: Tested across various edge conditions to confirm reliability of rule-based actioning.


Empirically determined that 100 training episodes produced optimal generalization, whereas extending to 101 episodes consistently induced overfitting, as evidenced by instability in reward convergence under the adjusted reward function.
