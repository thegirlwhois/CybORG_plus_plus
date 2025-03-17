# Load the trained model
model = DQN.load("zeek_dqn_model")
env = ZeekDQNEnv("zeek_logs.csv")

obs = env.reset()
for _ in range(10):
    action, _ = model.predict(obs)
    obs, reward, done, _ = env.step(action)
    print(f"Action: {action}, Reward: {reward}")
    if done:
        break
