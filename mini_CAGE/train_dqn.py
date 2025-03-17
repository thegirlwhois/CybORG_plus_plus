import numpy as np
from stable_baselines3 import DQN
from minimal import SimplifiedCAGE  # Import MiniCAGE environment

# Initialize MiniCAGE environment
env = SimplifiedCAGE(num_envs=1)

# Create the DQN model
model = DQN("MlpPolicy", env, verbose=1, learning_rate=0.0001, buffer_size=50000)

# Train the model
model.learn(total_timesteps=100000)

# Save the trained model
model.save("dqn_cyber_defense")

# Test the trained model
obs, _ = env.reset()
for _ in range(10):
    action, _ = model.predict(obs)
    obs, reward, done, _ = env.step(action)
    print(f"Action: {action}, Reward: {reward}")
    if done:
        obs, _ = env.reset()
