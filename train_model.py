# ... (after loading the df) ...

# Explicitly define the features we want to use
required_features = ['packet_length', 'protocol', 'tcp_flags', 'src_port', 'dst_port']

# Handle the empty values (NaN) seen in your CSV for UDP packets
df['src_port'] = df['src_port'].fillna(0)
df['dst_port'] = df['dst_port'].fillna(0)

features = df[required_features]
target = df['label']

# ... (rest of the training code) ...