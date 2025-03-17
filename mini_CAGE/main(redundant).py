from stable_baselines3 import DQN

# Load your Zeek environment
env = ZeekDQNEnv("zeek_logs.csv")

# Train the DQN model
model = DQN("MlpPolicy", env, verbose=1)
model.learn(total_timesteps=10000)

# Save the trained model
model.save("zeek_dqn_model")
