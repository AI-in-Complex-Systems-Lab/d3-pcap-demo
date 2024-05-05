import streamlit as st
from streamlit_d3graph import d3graph
import networkx as nx
from pcap_utils import process_pcap_file

G = nx.DiGraph()

# Process the PCAP file
process_pcap_file(G)


d3 = d3graph(verbose=60)
d3.graph(nx.adjacency_matrix(G).todense())
d3.set_node_properties(label=list(G.nodes), cmap='Set1')
d3.show(show_slider=False, save_button=False)
