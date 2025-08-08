import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({'font.size': 14})

data = np.loadtxt('cwnd_of_ack.txt')
time = data[:, 0] / 1000
cwnd = data[:, 1]
ssthresh = data[:, 2]
state = data[:, 4].astype(int)

interval = 1000
num_segments = int(np.ceil(time[-1] / interval))

# 修改颜色方案，使LOSS状态更明显
state_colors = {
    0: 'green',     # OPEN
    1: 'yellow',    # DISORDER 
    2: 'red',       # RECOVERY
    3: 'black'      # LOSS - 使用黑色
}

state_names = ["slow start", "congestion avoidance", "fast recover"]
used_states = set()

for i in range(num_segments):
    # ...existing code...
    plt.figure(figsize=(12, 8))
    used_states.clear()
    
    # 绘制ssthresh
    s = ssthresh[i * interval:(i + 1) * interval]  # Define 's' as a segment of 'ssthresh'
    st = state[i * interval:(i + 1) * interval]  # Define 'st' as a segment of 'state'
    t = time[i * interval:(i + 1) * interval]   # Define 't' as a segment of 'time'
    c = cwnd[i * interval:(i + 1) * interval]   # Define 'c' as a segment of 'cwnd'
    plt.plot(t, s, 'r--', label='ssthresh', linewidth=2)
    
    # 标记LOSS状态发生的位置
    for j in range(1, len(st)):
        if st[j] == 3:  # LOSS状态
            plt.axvline(x=t[j], color='black', linestyle=':', alpha=0.5)
            plt.axvspan(t[j], t[j+1] if j+1 < len(t) else t[-1], 
                       color='gray', alpha=0.2)
    
    # 为每个状态绘制一段折线
    last_idx = 0
    last_state = st[0]
    for j in range(1, len(st)):
        if st[j] != last_state:
            label = f'cwnd ({state_names[int(last_state)]})' if last_state not in used_states else None
            if last_state == 3:  # LOSS状态使用更粗的线
                linewidth = 3
            else:
                linewidth = 2
            plt.plot(t[last_idx:j+1], c[last_idx:j+1], 
                    color=state_colors[last_state],
                    linewidth=linewidth,
                    label=label)
            used_states.add(last_state)
            last_idx = j
            last_state = st[j]
    
    # 绘制最后一段
    label = f'cwnd ({state_names[int(last_state)]})' if last_state not in used_states else None
    linewidth = 3 if last_state == 3 else 2
    plt.plot(t[last_idx:], c[last_idx:], 
            color=state_colors[last_state],
            linewidth=linewidth,
            label=label)
    
    start_time = i * interval
    end_time = (i + 1) * interval if (i + 1) * interval <= time[-1] else int(time[-1])
    plt.title(f'TCP Congestion Control ({start_time}-{end_time}ms)', fontsize=16)
    plt.xlabel('ACK', fontsize=14)
    plt.ylabel('Window Size (bytes)', fontsize=14)
    
    plt.grid(True, alpha=0.3)
    plt.legend(fontsize=12)
    plt.tight_layout()
    
    plt.savefig(f'pic{i+1}_of_ack.png', dpi=300, bbox_inches='tight')
    plt.close()