// Copyright 2018 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1alpha3

import (
	"fmt"
	"time"

	listener "github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	accesslogconfig "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v2"
	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/filter/accesslog/v2"
	mongo_proxy "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/mongo_proxy/v2"
	mysql_proxy "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/mysql_proxy/v1alpha1"
	redis_proxy "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/redis_proxy/v2"
	dubbo_proxy "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/dubbo_proxy/v2alpha1"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher"
	route "github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
	tcp_proxy "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/tcp_proxy/v2"
	"github.com/envoyproxy/go-control-plane/pkg/conversion"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/golang/protobuf/ptypes"

	networking "istio.io/api/networking/v1alpha3"

	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	istio_route "istio.io/istio/pilot/pkg/networking/core/v1alpha3/route"
	"istio.io/istio/pilot/pkg/networking/util"
	"istio.io/istio/pkg/config/host"
	"istio.io/istio/pkg/config/protocol"
)

// redisOpTimeout is the default operation timeout for the Redis proxy filter.
var redisOpTimeout = 5 * time.Second

// buildInboundNetworkFilters generates a TCP proxy network filter on the inbound path
func buildInboundNetworkFilters(env *model.Environment, node *model.Proxy, instance *model.ServiceInstance) []*listener.Filter {
	clusterName := model.BuildSubsetKey(model.TrafficDirectionInbound, instance.Endpoint.ServicePort.Name,
		instance.Service.Hostname, instance.Endpoint.ServicePort.Port)
	tcpProxy := &tcp_proxy.TcpProxy{
		StatPrefix:       clusterName,
		ClusterSpecifier: &tcp_proxy.TcpProxy_Cluster{Cluster: clusterName},
	}
	tcpFilter := setAccessLogAndBuildTCPFilter(env, node, tcpProxy)
	return buildNetworkFiltersStack(node, instance.Endpoint.ServicePort, tcpFilter, clusterName, clusterName, nil)
}

// setAccessLog sets the AccessLog configuration in the given TcpProxy instance.
func setAccessLog(env *model.Environment, node *model.Proxy, config *tcp_proxy.TcpProxy) *tcp_proxy.TcpProxy {
	if env.Mesh.AccessLogFile != "" {
		fl := &accesslogconfig.FileAccessLog{
			Path: env.Mesh.AccessLogFile,
		}

		acc := &accesslog.AccessLog{
			Name: wellknown.FileAccessLog,
		}
		buildAccessLog(node, fl, env)

		if util.IsXDSMarshalingToAnyEnabled(node) {
			acc.ConfigType = &accesslog.AccessLog_TypedConfig{TypedConfig: util.MessageToAny(fl)}
		} else {
			c, _ := conversion.MessageToStruct(fl)
			acc.ConfigType = &accesslog.AccessLog_Config{Config: c}
		}

		config.AccessLog = append(config.AccessLog, acc)
	}

	// envoy als is not enabled for tcp
	return config
}

// setAccessLogAndBuildTCPFilter sets the AccessLog configuration in the given
// TcpProxy instance and builds a TCP filter out of it.
func setAccessLogAndBuildTCPFilter(env *model.Environment, node *model.Proxy, config *tcp_proxy.TcpProxy) *listener.Filter {
	setAccessLog(env, node, config)

	tcpFilter := &listener.Filter{
		Name: wellknown.TCPProxy,
	}
	if util.IsXDSMarshalingToAnyEnabled(node) {
		tcpFilter.ConfigType = &listener.Filter_TypedConfig{TypedConfig: util.MessageToAny(config)}
	} else {
		tcpFilter.ConfigType = &listener.Filter_Config{Config: util.MessageToStruct(config)}
	}
	return tcpFilter
}

// buildOutboundNetworkFiltersWithSingleDestination takes a single cluster name
// and builds a stack of network filters.
func buildOutboundNetworkFiltersWithSingleDestination(env *model.Environment, node *model.Proxy,
	clusterName string, port *model.Port) []*listener.Filter {

	tcpProxy := &tcp_proxy.TcpProxy{
		StatPrefix:       clusterName,
		ClusterSpecifier: &tcp_proxy.TcpProxy_Cluster{Cluster: clusterName},
		// TODO: Need to set other fields such as Idle timeouts
	}

	idleTimeout, err := time.ParseDuration(node.Metadata.IdleTimeout)
	if idleTimeout > 0 && err == nil {
		tcpProxy.IdleTimeout = ptypes.DurationProto(idleTimeout)
	}

	tcpFilter := setAccessLogAndBuildTCPFilter(env, node, tcpProxy)
	return buildNetworkFiltersStack(node, port, tcpFilter, clusterName, clusterName, nil)
}

// buildOutboundNetworkFiltersWithWeightedClusters takes a set of weighted
// destination routes and builds a stack of network filters.
func buildOutboundNetworkFiltersWithWeightedClusters(env *model.Environment, node *model.Proxy, routes []*networking.RouteDestination,
	push *model.PushContext, port *model.Port, configMeta model.ConfigMeta) []*listener.Filter {

	statPrefix := fmt.Sprintf("%s.%s", configMeta.Name, configMeta.Namespace)
	clusterSpecifier := &tcp_proxy.TcpProxy_WeightedClusters{
		WeightedClusters: &tcp_proxy.TcpProxy_WeightedCluster{},
	}

	proxyConfig := &tcp_proxy.TcpProxy{
		StatPrefix:       statPrefix,
		ClusterSpecifier: clusterSpecifier,
		// TODO: Need to set other fields such as Idle timeouts
	}

	idleTimeout, err := time.ParseDuration(node.Metadata.IdleTimeout)
	if idleTimeout > 0 && err == nil {
		proxyConfig.IdleTimeout = ptypes.DurationProto(idleTimeout)
	}

	for _, route := range routes {
		service := node.SidecarScope.ServiceForHostname(host.Name(route.Destination.Host), push.ServiceByHostnameAndNamespace)
		if route.Weight > 0 {
			clusterName := istio_route.GetDestinationCluster(route.Destination, service, port.Port)
			clusterSpecifier.WeightedClusters.Clusters = append(clusterSpecifier.WeightedClusters.Clusters, &tcp_proxy.TcpProxy_WeightedCluster_ClusterWeight{
				Name:   clusterName,
				Weight: uint32(route.Weight),
			})
		}
	}

	// TODO: Need to handle multiple cluster names for Redis
	clusterName := clusterSpecifier.WeightedClusters.Clusters[0].Name
	tcpFilter := setAccessLogAndBuildTCPFilter(env, node, proxyConfig)
	return buildNetworkFiltersStack(node, port, tcpFilter, statPrefix, clusterName, clusterSpecifier.WeightedClusters.Clusters)
}

// buildNetworkFiltersStack builds a slice of network filters based on
// the protocol in use and the given TCP filter instance.
func buildNetworkFiltersStack(node *model.Proxy, port *model.Port, tcpFilter *listener.Filter, statPrefix string, clusterName string, clusters []*tcp_proxy.TcpProxy_WeightedCluster_ClusterWeight) []*listener.Filter {
	filterstack := make([]*listener.Filter, 0)
	switch port.Protocol {
	case protocol.Mongo:
		filterstack = append(filterstack, buildMongoFilter(statPrefix, util.IsXDSMarshalingToAnyEnabled(node)), tcpFilter)
	case protocol.Redis:
		if features.EnableRedisFilter.Get() {
			// redis filter has route config, it is a terminating filter, no need append tcp filter.
			filterstack = append(filterstack, buildRedisFilter(statPrefix, clusterName, util.IsXDSMarshalingToAnyEnabled(node)))
		} else {
			filterstack = append(filterstack, tcpFilter)
		}
	case protocol.MySQL:
		if features.EnableMysqlFilter.Get() {
			filterstack = append(filterstack, buildMySQLFilter(statPrefix, util.IsXDSMarshalingToAnyEnabled(node)))
		}
		filterstack = append(filterstack, tcpFilter)
	case protocol.Dubbo:
		if features.EnableDubboFilter.Get() {
			// dubbo filter has route config, it is a terminating filter, no need append tcp filter.
			filterstack = append(filterstack, buildDubboFilter(statPrefix, clusterName, clusters, false))
		} else {
			filterstack = append(filterstack, tcpFilter)
		}
	default:
		filterstack = append(filterstack, tcpFilter)
	}

	return filterstack
}

// buildOutboundNetworkFilters generates a TCP proxy network filter for outbound
// connections. In addition, it generates protocol specific filters (e.g., Mongo
// filter).
func buildOutboundNetworkFilters(env *model.Environment, node *model.Proxy,
	routes []*networking.RouteDestination, push *model.PushContext,
	port *model.Port, configMeta model.ConfigMeta) []*listener.Filter {
	if len(routes) == 1 {
		service := node.SidecarScope.ServiceForHostname(host.Name(routes[0].Destination.Host), push.ServiceByHostnameAndNamespace)
		clusterName := istio_route.GetDestinationCluster(routes[0].Destination, service, port.Port)
		return buildOutboundNetworkFiltersWithSingleDestination(env, node, clusterName, port)
	}
	return buildOutboundNetworkFiltersWithWeightedClusters(env, node, routes, push, port, configMeta)
}

// buildMongoFilter builds an outbound Envoy MongoProxy filter.
func buildMongoFilter(statPrefix string, isXDSMarshalingToAnyEnabled bool) *listener.Filter {
	// TODO: add a watcher for /var/lib/istio/mongo/certs
	// if certs are found use, TLS or mTLS clusters for talking to MongoDB.
	// User is responsible for mounting those certs in the pod.
	mongoProxy := &mongo_proxy.MongoProxy{
		StatPrefix: statPrefix, // mongo stats are prefixed with mongo.<statPrefix> by Envoy
		// TODO enable faults in mongo
	}

	out := &listener.Filter{
		Name: wellknown.MongoProxy,
	}
	if isXDSMarshalingToAnyEnabled {
		out.ConfigType = &listener.Filter_TypedConfig{TypedConfig: util.MessageToAny(mongoProxy)}
	} else {
		out.ConfigType = &listener.Filter_Config{Config: util.MessageToStruct(mongoProxy)}
	}

	return out
}

// buildOutboundAutoPassthroughFilterStack builds a filter stack with sni_cluster and tcp_proxy
// used by auto_passthrough gateway servers
func buildOutboundAutoPassthroughFilterStack(env *model.Environment, node *model.Proxy, port *model.Port) []*listener.Filter {
	// First build tcp_proxy with access logs
	// then add sni_cluster to the front
	tcpProxy := buildOutboundNetworkFiltersWithSingleDestination(env, node, util.BlackHoleCluster, port)
	filterstack := make([]*listener.Filter, 0)
	filterstack = append(filterstack, &listener.Filter{
		Name: util.SniClusterFilter,
	})
	filterstack = append(filterstack, tcpProxy...)

	return filterstack
}

// buildRedisFilter builds an outbound Envoy RedisProxy filter.
// Currently, if multiple clusters are defined, one of them will be picked for
// configuring the Redis proxy.
func buildRedisFilter(statPrefix, clusterName string, isXDSMarshalingToAnyEnabled bool) *listener.Filter {
	redisProxy := &redis_proxy.RedisProxy{
		LatencyInMicros: true,       // redis latency stats are captured in micro seconds which is typically the case.
		StatPrefix:      statPrefix, // redis stats are prefixed with redis.<statPrefix> by Envoy
		Settings: &redis_proxy.RedisProxy_ConnPoolSettings{
			OpTimeout: ptypes.DurationProto(redisOpTimeout), // TODO: Make this user configurable
		},
		PrefixRoutes: &redis_proxy.RedisProxy_PrefixRoutes{
			CatchAllRoute: &redis_proxy.RedisProxy_PrefixRoutes_Route{
				Cluster: clusterName,
			},
		},
	}

	out := &listener.Filter{
		Name: wellknown.RedisProxy,
	}
	if isXDSMarshalingToAnyEnabled {
		out.ConfigType = &listener.Filter_TypedConfig{TypedConfig: util.MessageToAny(redisProxy)}
	} else {
		out.ConfigType = &listener.Filter_Config{Config: util.MessageToStruct(redisProxy)}
	}

	return out
}

// buildDubboFilter builds an outbound Envoy DubboProxy filter.
// Currently, if multiple clusters are defined, one of them will be picked for
// configuring the Dubbo proxy.
func buildDubboFilter(statPrefix, clusterName string, clusters []*tcp_proxy.TcpProxy_WeightedCluster_ClusterWeight, isXDSMarshalingToAnyEnabled bool) *listener.Filter {
	var routeAction *dubbo_proxy.RouteAction
	if clusters == nil {
		routeAction = &dubbo_proxy.RouteAction{
			ClusterSpecifier: &dubbo_proxy.RouteAction_Cluster{
				Cluster: clusterName,
			},
		}
	} else {
		var weightedCluster []*route.WeightedCluster_ClusterWeight
		for _, cluster := range clusters {
			weightedClusterName := cluster.Name
			weightedClusterWeight := cluster.Weight
			weightedClusterClusterWeight := &route.WeightedCluster_ClusterWeight{
				Name: weightedClusterName,
				Weight: &wrappers.UInt32Value{
					Value: weightedClusterWeight,
				},
			}
			weightedCluster = append(weightedCluster, weightedClusterClusterWeight)
		}
		routeAction = &dubbo_proxy.RouteAction{
			ClusterSpecifier: &dubbo_proxy.RouteAction_WeightedClusters{
				WeightedClusters: &route.WeightedCluster{
					Clusters: weightedCluster,
				},
			},
		}
	}
	dubboRoute := dubbo_proxy.Route{
		Match: &dubbo_proxy.RouteMatch{
			Method: &dubbo_proxy.MethodMatch{
				Name: &matcher.StringMatcher{
					MatchPattern: &matcher.StringMatcher_SafeRegex{
						SafeRegex: &matcher.RegexMatcher{
							Regex: "(.*?)",
							EngineType: &matcher.RegexMatcher_GoogleRe2{
								GoogleRe2: &matcher.RegexMatcher_GoogleRE2{
								},
							},
						},
					},
				},
			},
		},
		Route: routeAction,
	}
	routes := []*dubbo_proxy.Route{&dubboRoute}

	routeConfig := dubbo_proxy.RouteConfiguration{
		Name:      "local_route",
		Interface: ".*",
		Routes:    routes,
	}
	routeConfigs := []*dubbo_proxy.RouteConfiguration{&routeConfig}

	dubboFilter := dubbo_proxy.DubboFilter{
		Name: "envoy.filters.dubbo.router",
	}
	dubboFilters := []*dubbo_proxy.DubboFilter{&dubboFilter}

	dubboProxy := &dubbo_proxy.DubboProxy{
		StatPrefix:        statPrefix,                             // dubbo stats are prefixed with redis.<statPrefix> by Envoy
		ProtocolType:      dubbo_proxy.ProtocolType_Dubbo,         //dubbo prootocol type
		SerializationType: dubbo_proxy.SerializationType_Hessian2, // use Hessian2
		RouteConfig:       routeConfigs,
		DubboFilters:      dubboFilters,
	}

	out := &listener.Filter{
		Name: "envoy.filters.network.dubbo_proxy",
	}
	if isXDSMarshalingToAnyEnabled {
		out.ConfigType = &listener.Filter_TypedConfig{TypedConfig: util.MessageToAny(dubboProxy)}
	} else {
		out.ConfigType = &listener.Filter_Config{Config: util.MessageToStruct(dubboProxy)}
	}

	return out
}

// buildMySQLFilter builds an outbound Envoy MySQLProxy filter.
func buildMySQLFilter(statPrefix string, isXDSMarshalingToAnyEnabled bool) *listener.Filter {
	mySQLProxy := &mysql_proxy.MySQLProxy{
		StatPrefix: statPrefix, // MySQL stats are prefixed with mysql.<statPrefix> by Envoy.
	}

	out := &listener.Filter{
		Name: wellknown.MySQLProxy,
	}

	if isXDSMarshalingToAnyEnabled {
		out.ConfigType = &listener.Filter_TypedConfig{TypedConfig: util.MessageToAny(mySQLProxy)}
	} else {
		out.ConfigType = &listener.Filter_Config{Config: util.MessageToStruct(mySQLProxy)}
	}

	return out
}
