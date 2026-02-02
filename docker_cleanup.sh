#!/bin/bash

while true; do
	NODES=("minikube" "minikube-m02")
	
	for node in "${NODES[@]}"; do
		# Cleanup containers in each node
		minikube ssh -n $node -- docker container prune --force
	done
	
	sleep 60
done
