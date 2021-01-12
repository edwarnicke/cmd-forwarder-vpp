// Copyright (c) 2020 Cisco and/or its affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vppinit

import (
	"context"
	"fmt"
	"net"
	"time"

	"git.fd.io/govpp.git/api"
	"github.com/edwarnicke/govpp/binapi/af_packet"
	"github.com/edwarnicke/govpp/binapi/fib_types"
	interfaces "github.com/edwarnicke/govpp/binapi/interface"
	"github.com/edwarnicke/govpp/binapi/interface_types"
	"github.com/edwarnicke/govpp/binapi/ip"
	"github.com/networkservicemesh/sdk-vpp/pkg/tools/types"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/trace"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

func Must(IP net.IP, err error) net.IP {
	if err != nil {
		panic(fmt.Sprintf("error: %+v", err))
	}
	return IP
}

func LinkToAfPacket(ctx context.Context, vppConn api.Connection, IP net.IP) (net.IP, error) {
	link, addrs, routes, err := linkAddrsRoutes(ctx, IP)
	if err != nil {
		return nil, err
	}
	if link == nil {
		return IP, nil
	}
	afPacketCreate := &af_packet.AfPacketCreate{
		HwAddr:     types.ToVppMacAddress(&link.Attrs().HardwareAddr),
		HostIfName: link.Attrs().Name,
	}
	now := time.Now()
	afPacketCreateRsp, err := af_packet.NewServiceClient(vppConn).AfPacketCreate(ctx, afPacketCreate)
	if err != nil {
		return nil, err
	}
	trace.Log(ctx).
		WithField("swIfIndex", afPacketCreateRsp.SwIfIndex).
		WithField("duration", time.Since(now)).
		WithField("vppapi", "AfPacketCreate").Debug("completed")

	now = time.Now()
	_, err = interfaces.NewServiceClient(vppConn).SwInterfaceSetFlags(ctx, &interfaces.SwInterfaceSetFlags{
		SwIfIndex: afPacketCreateRsp.SwIfIndex,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	})
	if err != nil {
		return nil, err
	}
	trace.Log(ctx).
		WithField("swIfIndex", afPacketCreateRsp.SwIfIndex).
		WithField("duration", time.Since(now)).
		WithField("vppapi", "SwInterfaceSetFlags").Debug("completed")

	for _, addr := range addrs {
		if addr.IPNet != nil && addr.IPNet.IP.IsGlobalUnicast() && IP == nil {
			IP = addr.IPNet.IP
		}
		if addr.IPNet != nil && addr.IPNet.IP.Equal(IP) {
			now = time.Now()
			_, err = interfaces.NewServiceClient(vppConn).SwInterfaceAddDelAddress(ctx, &interfaces.SwInterfaceAddDelAddress{
				SwIfIndex: afPacketCreateRsp.SwIfIndex,
				IsAdd:     true,
				Prefix:    types.ToVppAddressWithPrefix(addr.IPNet),
			})
			trace.Log(ctx).
				WithField("swIfIndex", afPacketCreateRsp.SwIfIndex).
				WithField("prefix", addr.IPNet).
				WithField("isAdd", true).
				WithField("duration", time.Since(now)).
				WithField("vppapi", "SwInterfaceAddDelAddress").Debug("completed")
		}
	}

	for _, route := range routes {
		vppRoute := ip.IPRoute{
			StatsIndex: 0,
			Prefix:     types.ToVppPrefix(route.Dst),
			NPaths:     1,
			Paths: []fib_types.FibPath{
				{
					SwIfIndex: uint32(afPacketCreateRsp.SwIfIndex),
					TableID:   0,
					RpfID:     0,
					Weight:    1,
					Type:      fib_types.FIB_API_PATH_TYPE_NORMAL,
					Flags:     fib_types.FIB_API_PATH_FLAG_NONE,
					Proto:     types.IsV6toFibProto(IP.To4() == nil),
				},
			},
		}
		if route.Gw != nil {
			vppRoute.Paths[0].Nh.Address = types.ToVppAddress(route.Gw).Un
		}
		now = time.Now()
		_, err = ip.NewServiceClient(vppConn).IPRouteAddDel(ctx, &ip.IPRouteAddDel{
			IsAdd: true,
			Route: vppRoute,
		})
		if err != nil {
			return nil, err
		}
		trace.Log(ctx).
			WithField("swIfIndex", afPacketCreateRsp.SwIfIndex).
			WithField("prefix", vppRoute.Prefix).
			WithField("isAdd", true).
			WithField("duration", time.Since(now)).
			WithField("vppapi", "IPRouteAddDel").Debug("completed")
	}

	//aclAddDelete := &acl.ACLAddReplace{
	//	ACLIndex: ^uint32(0),
	//	Tag:      "forwarder-deny-all",
	//	Count:    1,
	//	R: []acl_types.ACLRule{
	//		{
	//			IsPermit: acl_types.ACL_ACTION_API_DENY,
	//		},
	//	},
	//}
	//now = time.Now()
	//aclAddDelRsp, err := acl.NewServiceClient(vppConn).ACLAddReplace(ctx, aclAddDelete)
	//if err != nil {
	//	return nil, errors.WithStack(err)
	//}
	//trace.Log(ctx).
	//	WithField("aclIndex", aclAddDelRsp.ACLIndex).
	//	WithField("duration", time.Since(now)).
	//	WithField("vppapi", "ACLAddReplace").Debug("completed")
	//
	//aclInterfaceSetACLList := acl.ACLInterfaceSetACLList{
	//	SwIfIndex: afPacketCreateRsp.SwIfIndex,
	//	Count:     2,
	//	NInput:    1,
	//	Acls: []uint32{
	//		aclAddDelRsp.ACLIndex,
	//		aclAddDelRsp.ACLIndex,
	//	},
	//}
	//now = time.Now()
	//_, err = acl.NewServiceClient(vppConn).ACLInterfaceSetACLList(ctx, &aclInterfaceSetACLList)
	//if err != nil {
	//	return nil, errors.WithStack(err)
	//}
	//trace.Log(ctx).
	//	WithField("swIfIndex", aclInterfaceSetACLList.SwIfIndex).
	//	WithField("acls", aclInterfaceSetACLList.Acls).
	//	WithField("NInput", aclInterfaceSetACLList.NInput).
	//	WithField("duration", time.Since(now)).
	//	WithField("vppapi", "ACLInterfaceSetACLList").Debug("completed")
	return IP, nil
}

func linkAddrsRoutes(ctx context.Context, IP net.IP) (netlink.Link, []netlink.Addr, []netlink.Route, error) {
	link, err := linkByIP(ctx, IP)
	if err != nil {
		return nil, nil, nil, err
	}
	if link == nil {
		return nil, nil, nil, nil
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "error getting addrs for link %s", link.Attrs().Name)
	}
	routes, err := netlink.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "could not find routes for link %s", link.Attrs().Name)
	}
	return link, addrs, routes, nil
}

func defaultRouteLink(ctx context.Context) (netlink.Link, error) {
	now := time.Now()
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get routes")
	}

	trace.Log(ctx).
		WithField("duration", time.Since(now)).
		WithField("netlink", "RouteList").Debug("completed")

	for _, route := range routes {
		// Is it a default route?
		if route.Dst != nil {
			ones, _ := route.Dst.Mask.Size()
			if ones == 0 && (route.Dst.IP.Equal(net.IPv4zero) || route.Dst.IP.Equal(net.IPv6zero)) {
				return netlink.LinkByIndex(route.LinkIndex)
			}
			continue
		}
		if route.Scope == netlink.SCOPE_UNIVERSE {
			return netlink.LinkByIndex(route.LinkIndex)
		}
	}
	return nil, errors.New("no link found for default route")
}

func linkByIP(ctx context.Context, IP net.IP) (netlink.Link, error) {
	if IP == nil {
		return defaultRouteLink(ctx)
	}
	links, err := netlink.LinkList()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get links")
	}
	for _, link := range links {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, errors.Wrap(err, "could not find links for default routes")
		}
		for _, addr := range addrs {
			if addr.IPNet != nil && addr.IPNet.IP.Equal(IP) {
				return link, nil
			}
		}
	}
	return nil, nil
}
