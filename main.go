package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	dnspod "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}
	// webhook 服务注册
	cmd.RunWebhookServer(GroupName,
		&dnspodSolver{},
	)
}

// dnspodSolver
// 腾讯DNSSolver
type dnspodSolver struct {
	k8sclient      *kubernetes.Clientset
	dnspodClie     *dnspod.Client
	isDisableCHAME bool //是否启用禁止CHAME
}

type dnspodConfig struct {
	SecretId     cmmetav1.SecretKeySelector `json:"secretIdSecretRef"`
	SecretKey    cmmetav1.SecretKeySelector `json:"secretKeySecretRef"`
	DisableCHAME bool                       `json:"disableCHAME"`
}

// 定义Solver名称
func (c *dnspodSolver) Name() string {
	return "dnspod-solver"
}

func (c *dnspodSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("Present challenge dnsName: %v fqdn: %v Key: %v", ch.DNSName, ch.ResolvedFQDN, ch.Key)
	c.InitDNSPodClie(ch)                                      //初始化客户端
	domain, sub := analysis(ch.ResolvedZone, ch.ResolvedFQDN) //处理k8s的参数给客户端用
	req := NewRequest(domain, SetSub(sub), SetValue(ch.Key), SetRecordType("TXT"))
	//创建TXT记录
	_, err := c.CreateRecord(req)
	if err != nil {
		klog.Infof("Failed to create TXT record! Error issue: %v", err)
		return err
	}
	c.IsChame(domain, DisabledStatus()) //禁用CHAME，内部根据配置判断是否禁用
	return nil
}

// 清理记录
func (c *dnspodSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("Clean challenge dnsName: %v fqdn: %v Key: %v", ch.DNSName, ch.ResolvedFQDN, ch.Key)
	c.InitDNSPodClie(ch)                                      //初始化客户端
	domain, sub := analysis(ch.ResolvedZone, ch.ResolvedFQDN) //处理k8s的参数给客户端用
	req := NewRequest(domain, SetSub(sub), SetValue(ch.Key))
	err := c.DeleteTXTRecord(req)
	if err != nil {
		klog.Infof("Delete TXT record failed! Error issue: %v", err)
		return err
	}
	c.IsChame(domain, EnableStatus()) //启用CHAME，内部根据配置判断是否禁用
	return nil
}

// Initialize
// webhook首次启动时，将调用Initialize
func (c *dnspodSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	klog.Infoln("webhook is load Initialize")
	k8sClient, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	c.k8sclient = k8sClient
	return nil
}

// InitDNSPodClie 初始化dnspod客户端
func (c *dnspodSolver) InitDNSPodClie(ch *v1alpha1.ChallengeRequest) error {
	klog.Infoln("Initialize dnspod client")
	cfg, _ := loadConfig(ch.Config)
	klog.Infof("Load configuration file key name: %s", cfg.SecretId.Name)
	// 读取配置相关数据
	secretID, err := c.loadSecretData(cfg.SecretId, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("failed to get domain id %s: %v", ch.ResolvedZone, err)
	}
	secretKey, err := c.loadSecretData(cfg.SecretKey, ch.ResourceNamespace)
	if err != nil {
		return fmt.Errorf("failed to get key id %s: %v", ch.ResolvedZone, err)
	}
	// 初始化客户端
	credential := common.NewCredential(string(secretID), string(secretKey))
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "dnspod.tencentcloudapi.com" //就近接入非金融区
	client, err := dnspod.NewClient(credential, "", cpf)
	if err != nil {
		return err
	}
	c.isDisableCHAME = cfg.DisableCHAME
	c.dnspodClie = client //初始化赋值
	return nil
}

// 加载Secret数据
func (c *dnspodSolver) loadSecretData(selector cmmetav1.SecretKeySelector, ns string) ([]byte, error) {
	secret, err := c.k8sclient.CoreV1().Secrets(ns).Get(context.TODO(), selector.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to load secret %q errors:%v", ns+"/"+selector.Name, err)
	}
	if data, ok := secret.Data[selector.Key]; ok {
		return data, nil
	}
	return nil, fmt.Errorf("no key %q in secret %q", selector.Key, ns+"/"+selector.Name)
}

// 加载配置文件
func loadConfig(cfgJSON *extapi.JSON) (dnspodConfig, error) {
	cfg := dnspodConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	klog.Infoln("load config file ...")
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		klog.Errorf("decoded solver config err: %v", err)
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}
	return cfg, nil
}

// 处理域名参数
func analysis(zone, fqdn string) (domain, sub string) {
	domain = util.UnFqdn(zone)
	sub = util.UnFqdn(fqdn[:len(fqdn)-len(zone)])
	return
}

type dnspodReq struct {
	domain     *string //域名
	domainID   *uint64 //域名ID
	sub        *string //主机头
	recordline *string //线路
	recordType *string //记录类型
	recordId   *uint64 //记录ID
	value      *string //赋值
	Status     *string //状态
}

type Option func(*dnspodReq)

func SetDomainID(id uint64) Option { return func(dr *dnspodReq) { dr.domainID = common.Uint64Ptr(id) } }
func SetSub(sub string) Option     { return func(dr *dnspodReq) { dr.sub = common.StringPtr(sub) } }
func SetValue(value string) Option { return func(dr *dnspodReq) { dr.value = common.StringPtr(value) } }
func SetRecordLine(linetxt string) Option {
	return func(dr *dnspodReq) { dr.recordline = common.StringPtr(linetxt) }
}
func SetRecordType(rtype string) Option {
	return func(dr *dnspodReq) { dr.recordType = common.StringPtr(rtype) }
}
func SetRecordId(id uint64) Option { return func(dr *dnspodReq) { dr.recordId = common.Uint64Ptr(id) } }
func DisabledStatus() Option       { return func(dr *dnspodReq) { dr.Status = common.StringPtr("DISABLE") } }
func EnableStatus() Option         { return func(dr *dnspodReq) { dr.Status = common.StringPtr("ENABLE") } }

func NewRequest(zone string, options ...Option) *dnspodReq {
	req := &dnspodReq{
		domain:     common.StringPtr(zone),
		recordline: common.StringPtr("默认"),
		Status:     common.StringPtr("ENABLE"),
	}
	for _, option := range options {
		option(req)
	}
	return req
}

// 禁用CHAME记录，不然影响DNS01查询结果
var DisableCHAME = []string{
	"@",
	"*",
}

// 获取托管域名信息
func (c *dnspodSolver) getHostedZone(dreq *dnspodReq) (*uint64, *string, error) {
	req := dnspod.NewDescribeDomainRequest()
	req.Domain = dreq.domain
	resp, err := c.dnspodClie.DescribeDomain(req)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		klog.Errorf("DescribeDomain An API error has returned: %s", err)
		return nil, nil, err
	}
	if resp.Response == nil || resp.Response.DomainInfo == nil {
		return nil, nil, fmt.Errorf("no list of domain names found")
	}
	domain := resp.Response.DomainInfo
	return domain.DomainId, domain.Domain, nil
}

// 创建TXT记录(只支持国内，国外不支持先弃用)
func (c *dnspodSolver) CreateTXTRecord(dreq *dnspodReq) (*uint64, error) {
	// 参数初始化
	req := dnspod.NewCreateTXTRecordRequest()
	req.Domain = dreq.domain
	req.SubDomain = dreq.sub
	req.Value = dreq.value
	req.RecordLine = dreq.recordline
	//创建TXT记录
	resp, err := c.dnspodClie.CreateTXTRecord(req)
	if sdkerr, ok := err.(*errors.TencentCloudSDKError); ok {
		//这里是已经有TXT记录了，我这里直接使用API处理了
		if sdkerr.Code == "InvalidParameter.DomainRecordExist" {
			err = c.DeleteTXTRecord(dreq)
			if err != nil {
				return nil, err
			}
			return c.CreateTXTRecord(dreq)
		}
		klog.Errorf("CreateTXTRecord An API error has returned: %s", err)
		return nil, err
	}
	if resp.Response == nil {
		return nil, fmt.Errorf("add TXT record error")
	}
	return resp.Response.RecordId, nil
}

// 创建一条记录
func (c *dnspodSolver) CreateRecord(dreq *dnspodReq) (*uint64, error) {
	//初始化参数
	req := dnspod.NewCreateRecordRequest()
	req.Domain = dreq.domain
	req.SubDomain = dreq.sub
	req.Value = dreq.value
	req.RecordLine = dreq.recordline
	req.RecordType = dreq.recordType
	//创建记录
	resp, err := c.dnspodClie.CreateRecord(req)
	if sdkerr, ok := err.(*errors.TencentCloudSDKError); ok {
		//这里是已经有记录了，我这里直接使用API处理了
		if sdkerr.Code == "InvalidParameter.DomainRecordExist" {
			err = c.DeleteTXTRecord(dreq)
			if err != nil {
				return nil, err
			}
			return c.CreateRecord(dreq)
		}
		klog.Errorf("CreateTXTRecord An API error has returned: %s", err)
		return nil, err
	}
	if resp.Response == nil {
		return nil, fmt.Errorf("add TXT record error")
	}
	return resp.Response.RecordId, nil
}

// 删除记录
func (c *dnspodSolver) DeleteRecord(dreq *dnspodReq) error {
	// 参数初始化
	req := dnspod.NewDeleteRecordRequest()
	req.Domain = dreq.domain
	req.RecordId = dreq.recordId
	//删除记录
	resp, err := c.dnspodClie.DeleteRecord(req)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		klog.Errorf("DeleteRecord An API error has returned: %s", err)
		return err
	}
	if resp.Response == nil {
		return fmt.Errorf("delete record error")
	}
	return nil
}

// 修改记录
func (c *dnspodSolver) ModifyRecord(dreq *dnspodReq) error {
	// 参数初始化
	req := dnspod.NewModifyRecordRequest()
	req.RecordId = dreq.recordId
	req.Domain = dreq.domain
	req.RecordType = dreq.recordType
	req.RecordLine = dreq.recordline
	req.Value = dreq.value
	req.Status = dreq.Status
	resp, err := c.dnspodClie.ModifyRecord(req)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		klog.Errorf("ModifyRecord An API error has returned: %s", err)
		return err
	}
	if resp.Response == nil {
		return fmt.Errorf("odify record error")
	}
	return nil
}

// 获取域名记录列表
func (c *dnspodSolver) DescribeRecordList(dreq *dnspodReq) (recordlist []*dnspod.RecordListItem, err error) {
	// 参数初始化
	req := dnspod.NewDescribeRecordListRequest()
	req.Domain = dreq.domain
	req.DomainId = dreq.domainID
	req.Subdomain = dreq.sub
	req.RecordType = dreq.recordType
	req.RecordLine = dreq.recordline
	resp, err := c.dnspodClie.DescribeRecordList(req)
	if sdkerr, ok := err.(*errors.TencentCloudSDKError); ok {
		if sdkerr.Code == "ResourceNotFound.NoDataOfRecord" {
			return nil, nil
		}
		klog.Errorf("DescribeRecordList An API error has returned: %s", err)
		return nil, err
	}
	if resp.Response == nil || len(resp.Response.RecordList) == 0 {
		return nil, fmt.Errorf("error in obtaining domain name record list")
	}
	recordlist = resp.Response.RecordList
	return
}

// 获取记录ID
func (c *dnspodSolver) GetRecordID(dreq *dnspodReq) (recordids []*uint64, err error) {
	recordlist, err := c.DescribeRecordList(dreq)
	if err != nil {
		return nil, err
	}
	for _, record := range recordlist {
		recordids = append(recordids, record.RecordId)
	}
	return
}

// 开启是否禁用CHAME
func (c *dnspodSolver) IsChame(zone string, options ...Option) {
	if !c.isDisableCHAME {
		klog.Infof("The domain name [% s] has not enabled automatic disabling of CHAME mode", zone)
		return
	}
	klog.Infof("Domain name [%s] enables automatic disabling of CHAME mode.", zone)
	for _, sub := range DisableCHAME {
		req := NewRequest(zone, SetSub(sub), SetRecordType("CNAME"))
		recordlist, err := c.DescribeRecordList(req) //查找记录
		if err != nil {
			klog.Infof("Domain name [%s] cannot find corresponding CHAME record for [%s]", zone, sub)
			continue
		}
		for _, record := range recordlist {
			options = append(options, SetRecordId(*record.RecordId))
			options = append(options, SetRecordType(*record.Type))
			options = append(options, SetRecordLine(*record.Line))
			options = append(options, SetValue(*record.Value))
			options = append(options, SetSub(*record.Name))
			req = NewRequest(zone, options...)
			err = c.ModifyRecord(req) //修改记录
			if err != nil {
				klog.Infof("Domain name [%s] modification [%s] corresponding CHAME record error %s", zone, sub, err)
				continue
			}
		}
	}
}

// 删除指定TXT记录
func (c *dnspodSolver) DeleteTXTRecord(req *dnspodReq) error {
	SetRecordType("TXT")(req)
	recordids, err := c.GetRecordID(req)
	if err != nil {
		klog.Infof("Domain name [%s] cannot find corresponding CHAME record for [%s]", *req.domain, *req.sub)
		return err
	}
	for _, recordid := range recordids {
		req = NewRequest(*req.domain, SetRecordId(*recordid))
		return c.DeleteRecord(req)
	}
	return nil
}
