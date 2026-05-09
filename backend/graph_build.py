import networkx as nx
def build_graph_from_events(events):
    # Aggregate traffic events into a directed host-to-host graph.
    G = nx.DiGraph()
    for ev in events:
        src = ev.get("src_ip")
        dst = ev.get("dst_ip")
        if not src or not dst:
            continue
        # Only keep events that have both endpoints.
        G.add_node(src, type='host')
        G.add_node(dst, type='host')
        if G.has_edge(src, dst):
            # Update the running edge summary for repeated communication.
            G[src][dst]['count'] += 1
            G[src][dst]['last_seen'] = ev.get('timestamp')
        else:
            # Store per-edge metadata for later inspection or visualization.
            G.add_edge(src, dst, count=1, ports=set([ev.get('dst_port')]), protos=set([ev.get('protocol')]), last_seen=ev.get('timestamp'))
    return G
def serialize_graph(G):

    # Convert the NetworkX graph into JSON-friendly node and edge records.
    nodes = [{"id": n, **G.nodes[n]} for n in G.nodes()]
    edges = []
    for u,v,data in G.edges(data=True):
        # Convert sets to lists so the result can be serialized cleanly.
        d = dict(data)
        for k in list(d.keys()):
            if isinstance(d[k], set):
                d[k] = list(d[k])
        edges.append({"source": u, "target": v, **d})
    return {"nodes": nodes, "edges": edges}
