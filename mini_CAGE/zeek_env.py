import gym
import numpy as np
import pandas as pd
from gym import spaces

class ZeekDQNEnv(gym.Env):
    def __init__(self, log_file):
        super(ZeekDQNEnv, self).__init__()
        
        # Load Zeek logs
        self.zeek_data = pd.read_csv(log_file)
        self.current_index = 0
        
        # Define state space (example: 5 features from Zeek logs)
        self.observation_space = spaces.Box(low=0, high=255, shape=(5,), dtype=np.float32)
        
        # Define action space (0: Ignore, 1: Alert, 2: Block)
        self.action_space = spaces.Discrete(3)
        
        # Reward system
        self.attack_detected = self.zeek_data['attack'].values  # 1 if attack, 0 if normal
        
    def reset(self):
        self.current_index = 0
        return self._get_state()
    
    def _get_state(self):
        row = self.zeek_data.iloc[self.current_index]
        state = np.array([row['src_ip'], row['dst_ip'], row['protocol'], row['bytes'], row['duration']])
        return state.astype(np.float32)
    
    def step(self, action):
        reward = 0
        done = False
        
        # Check if attack was real
        is_attack = self.attack_detected[self.current_index]
        
        if action == 1 and is_attack:  # Alert on attack → Good
            reward = +10  
        elif action == 1 and not is_attack:  # False positive
            reward = -5  
        elif action == 2 and is_attack:  # Blocked attack → Best reward
            reward = +20  
        elif action == 2 and not is_attack:  # Blocking normal traffic → Bad
            reward = -10  
        
        # Move to the next log entry
        self.current_index += 1
        if self.current_index >= len(self.zeek_data):
            done = True
        
        return self._get_state(), reward, done, {}
    
# Example usage
if __name__ == "__main__":
    env = ZeekDQNEnv("zeek_logs.csv")
    obs = env.reset()
    
    for _ in range(10):
        action = env.action_space.sample()  # Random action (0, 1, or 2)
        obs, reward, done, _ = env.step(action)
        print(f"Action: {action}, Reward: {reward}")
        if done:
            break
