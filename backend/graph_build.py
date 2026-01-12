import networkx as nx
def build_graph_from_events(events):
    G = nx.DiGraph()
    for ev in events:
        src = ev.get("src_ip")
        dst = ev.get("dst_ip")
        if not src or not dst:
            continue
        G.add_node(src, type='host')
        G.add_node(dst, type='host')
        if G.has_edge(src, dst):
            G[src][dst]['count'] += 1
            G[src][dst]['last_seen'] = ev.get('timestamp')
        else:
            G.add_edge(src, dst, count=1, ports=set([ev.get('dst_port')]), protos=set([ev.get('protocol')]), last_seen=ev.get('timestamp'))
    return G
def serialize_graph(G):

    nodes = [{"id": n, **G.nodes[n]} for n in G.nodes()]
    edges = []
    for u,v,data in G.edges(data=True):
        # convert sets to lists for JSON
        d = dict(data)
        for k in list(d.keys()):
            if isinstance(d[k], set):
                d[k] = list(d[k])
        edges.append({"source": u, "target": v, **d})
    return {"nodes": nodes, "edges": edges}
