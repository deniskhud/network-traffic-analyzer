#ifndef CLI_HPP
#define CLI_HPP
#include "../../cmake-build-debug/_deps/ftxui-src/src/ftxui/dom/box_helper.hpp"
#include "../packet/packet.hpp"
#include "ftxui/component/animation.hpp"
#include "ftxui/dom/elements.hpp"
struct List {
	List* prev;
	List* next;
	List* begin;
	List* end;
	Packet* packet;
};
//queues
void addNode(List* list, Packet* packet);
void eraseNode(List* list, Packet* packet);


std::string convert_tproto(TransportProtocol p);
std::string convert_appproto(TransportProtocol p);
std::string convert_ip(TransportProtocol p);


#endif //CLI_HPP
