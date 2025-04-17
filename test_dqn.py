import numpy as np
import torch
from stable_baselines3 import DQN

# Load trained model (no retraining)
model = DQN.load("dqn_cyber_defense")

# Ensure model is in strict evaluation mode
model.policy.eval()

# Freeze model parameters
for param in model.policy.parameters():
    param.requires_grad = False

# New observation pattern - Example (Shape: (52,))
obs = np.array([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
], dtype=np.float32) #no

obs1 = np.array([
    0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
], dtype=np.float32) #yes

obs2 = np.array([
    1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
], dtype=np.float32) #no

obs3=np.random.randint(1, 2, size=52).astype(np.float32)


obs4 = np.array([
    0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
], dtype=np.float32) #no

print("Initial Observation:", obs4)


done = False
with torch.no_grad():  # Disable gradients
    while not done:
        # Get the model's action
        action, _ = model.predict(obs4, deterministic=True)

        # Simulate environment step (replace with actual interaction logic)
        print(f"Action Taken: {action}")

        # Example: Simulated reward and done flag (replace with real values)
        reward = 5 if action == 2 else -45
        done = True

        print(f"Reward: {reward}, Done: {done}")
        
        # Send alert if an attack is detected
        if reward == 5:
            print("ALERT: Possible attack detected!")

# Final result
if reward == 5:
    print("Detection SUCCESS")
else:
    print("Nothing to detect")
