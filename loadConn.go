package goStrongswanVici

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type Connection struct {
	ConnConf map[string]IKEConf `json:"connections"`
}

type IKEConf struct {
	LocalAddrs  []string               `json:"local_addrs"`
	RemoteAddrs []string               `json:"remote_addrs,omitempty"`
	LocalPort   string                 `json:"local_port,omitempty"`
	RemotePort  string                 `json:"remote_port,omitempty"`
	Proposals   []string               `json:"proposals,omitempty"`
	Vips        []string               `json:"vips,omitempty"`
	Version     string                 `json:"version"` //1 for ikev1, 0 for ikev1 & ikev2
	Encap       string                 `json:"encap"`   //yes,no
	KeyingTries string                 `json:"keyingtries"`
	RekeyTime   string                 `json:"rekey_time"`
	DPDDelay    string                 `json:"dpd_delay,omitempty"`
	LocalAuth   AuthConf               `json:"local-1"`
	RemoteAuth  AuthConf               `json:"remote-1"`
	Pools       []string               `json:"pools,omitempty"`
	Children    map[string]ChildSAConf `json:"children"`
	Mobike      string                 `json:"mobike,omitempty"`
}

type AuthConf struct {
	ID         string   `json:"id"`
	Round      string   `json:"round,omitempty"`
	AuthMethod string   `json:"auth"` // (psk|pubkey)
	EAP_ID     string   `json:"eap_id,omitempty"`
	PubKeys    []string `json:"pubkeys,omitempty"` // PEM encoded public keys
	Certs      []string `json:"certs,omitempty"`   // PEM encoded certificates
	Class      string   `json:"class,omitempty"`
	Cacerts    []string `json:"cacerts,omitempty"` // PEM encoded CA certificates
}

type ChildSAConf struct {
	Local_ts      []string `json:"local-ts"`
	Remote_ts     []string `json:"remote-ts"`
	ESPProposals  []string `json:"esp_proposals,omitempty"` //aes128-sha1_modp1024
	StartAction   string   `json:"start_action"`            //none,trap,start
	CloseAction   string   `json:"close_action"`
	ReqID         string   `json:"reqid,omitempty"`
	RekeyTime     string   `json:"rekey_time"`
	ReplayWindow  string   `json:"replay_window,omitempty"`
	Mode          string   `json:"mode"`
	InstallPolicy string   `json:"policies"`
	UpDown        string   `json:"updown,omitempty"`
	Priority      string   `json:"priority,omitempty"`
	MarkIn        string   `json:"mark_in,omitempty"`
	MarkOut       string   `json:"mark_out,omitempty"`
	DpdAction     string   `json:"dpd_action,omitempty"`
	LifeTime      string   `json:"life_time,omitempty"`
}

// SetPublicKeys is a helper method that converts Public Keys to x509 PKIX PEM format
// Supported formats are those implemented by x509.MarshalPKIXPublicKey
func (a *AuthConf) SetPublicKeys(keys []crypto.PublicKey) error {
	var newKeys []string

	for _, key := range keys {
		asn1Bytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return fmt.Errorf("Error marshaling key: %v", err)
		}
		pemKey := pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: asn1Bytes,
		}
		pemBytes := pem.EncodeToMemory(&pemKey)
		newKeys = append(newKeys, string(pemBytes))
	}

	a.PubKeys = newKeys
	return nil
}

func (c *ClientConn) LoadConn(conn *map[string]IKEConf) error {
	requestMap := &map[string]interface{}{}

	err := ConvertToGeneral(conn, requestMap)

	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	msg, err := c.Request("load-conn", *requestMap)

	if msg["success"] != "yes" {
		return fmt.Errorf("unsuccessful LoadConn: %v", msg["errmsg"])
	}

	return nil
}
