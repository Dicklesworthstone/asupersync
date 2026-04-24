def rfc_adjusted(latest_rtt, min_rtt, ack_delay):
    adjusted_rtt = latest_rtt
    if min_rtt + ack_delay < latest_rtt:
        adjusted_rtt = latest_rtt - ack_delay
    return adjusted_rtt

def my_adjusted(sample_micros, min_rtt, ack_delay_micros):
    return sample_micros - min(ack_delay_micros, sample_micros - min_rtt)

print(f"RFC: {rfc_adjusted(100, 50, 60)}")
print(f"My:  {my_adjusted(100, 50, 60)}")
