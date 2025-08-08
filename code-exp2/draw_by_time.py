import numpy as np
import matplotlib.pyplot as plt

# 设置字体大小
plt.rcParams.update({'font.size': 14})

# 加载数据
data = np.loadtxt('cwnd_of_time.txt')
time_us = data[:, 0]         # 时间（微秒）
cwnd = data[:, 1]            # 拥塞窗口大小
ssthresh = data[:, 2]        # 慢启动阈值
state = data[:, 4].astype(int)  # 状态列

# 将时间从微秒转换为毫秒
time_ms = time_us / 1000

# 分段间隔（单位：ms）
interval = 1000
num_segments = int(np.ceil(time_ms[-1] / interval))

# 修改颜色方案，使 LOSS 状态更明显
state_colors = {
    0: 'green',     # OPEN
    1: 'yellow',    # DISORDER 
    2: 'red',       # RECOVERY
    3: 'black'      # LOSS - 使用黑色
}

state_names = ["slow start", "congestion avoidance", "fast recover"]

for i in range(num_segments):
    start_idx = i * interval
    end_idx = (i + 1) * interval

    # 找到当前时间段的数据索引范围
    start_time = start_idx
    end_time = end_idx

    # 用布尔索引提取当前时间段的数据
    mask = (time_ms >= start_time) & (time_ms < end_time)
    t_segment = time_ms[mask]
    c_segment = cwnd[mask]
    s_segment = ssthresh[mask]
    st_segment = state[mask]

    if len(t_segment) == 0:
        continue  # 跳过空段

    # 创建绘图
    plt.figure(figsize=(12, 8))
    used_states = set()

    # 绘制 ssthresh 曲线（红色虚线）
    plt.plot(t_segment, s_segment, 'r--', label='ssthresh', linewidth=2)

    # 标记 LOSS 状态发生的位置
    for j in range(1, len(st_segment)):
        if st_segment[j] == 3:  # LOSS 状态
            plt.axvline(x=t_segment[j], color='black', linestyle=':', alpha=0.5)
            plt.axvspan(t_segment[j], t_segment[j+1] if j+1 < len(t_segment) else t_segment[-1],
                       color='gray', alpha=0.2)

    # 为每个状态绘制一段折线
    last_idx = 0
    last_state = st_segment[0]
    for j in range(1, len(st_segment)):
        if st_segment[j] != last_state:
            label = f'cwnd ({state_names[last_state]})' if last_state not in used_states else None
            linewidth = 3 if last_state == 3 else 2
            plt.plot(t_segment[last_idx:j+1], c_segment[last_idx:j+1],
                    color=state_colors[last_state],
                    linewidth=linewidth,
                    label=label)
            used_states.add(last_state)
            last_idx = j
            last_state = st_segment[j]

    # 绘制最后一段
    label = f'cwnd ({state_names[last_state]})' if last_state not in used_states else None
    linewidth = 3 if last_state == 3 else 2
    plt.plot(t_segment[last_idx:], c_segment[last_idx:],
            color=state_colors[last_state],
            linewidth=linewidth,
            label=label)

    # 设置图表标题和坐标轴标签
    plot_start = int(start_time)
    plot_end = int(min(end_time, time_ms[-1]))
    plt.title(f'TCP Congestion Control ({plot_start}-{plot_end}ms)', fontsize=16)
    plt.xlabel('Time (ms)', fontsize=14)
    plt.ylabel('Window Size (bytes)', fontsize=14)

    # 添加网格和图例
    plt.grid(True, alpha=0.3)
    plt.legend(fontsize=12)
    plt.tight_layout()

    # 保存图像
    plt.savefig(f'pic{i+1}_of_time.png', dpi=300, bbox_inches='tight')

    # 关闭当前图像，避免内存问题
    plt.close()