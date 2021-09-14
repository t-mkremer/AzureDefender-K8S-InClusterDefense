package main

import (
	"github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/dataproviders/arg"
	argqueries "github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/dataproviders/arg/queries"
	"github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/infra/azureauth"
	azureauthwrappers "github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/infra/azureauth/wrappers"
	registryauthazure "github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/infra/registry/acrauth"
	"github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/infra/registry/crane"
	registrywrappers "github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/infra/registry/wrappers"
	"github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/tag2digest"
	argbase "github.com/Azure/azure-sdk-for-go/services/resourcegraph/mgmt/2021-03-01/resourcegraph"
	"k8s.io/client-go/kubernetes"
	"log"
	"time"
	"net/http"
	k8sclientconfig "sigs.k8s.io/controller-runtime/pkg/client/config"
	"github.com/Azure/AzureDefender-K8S-InClusterDefense/cmd/webhook"
	"github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/azdsecinfo"
	"github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/infra/config"
	"github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/infra/instrumentation"
	"github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/infra/instrumentation/tivan"
	"github.com/Azure/AzureDefender-K8S-InClusterDefense/pkg/infra/instrumentation/trace"
	"os"
)

const (
	_configFileKey = "CONFIG_FILE"
)

// main is the entrypoint to AzureDefenderInClusterDefense .
func main() {
	configFile := os.Getenv(_configFileKey)
	if len(configFile) == 0 {
		log.Fatalf("%v env variable is not defined.", _configFileKey)
	}
	// Load configuration
	AppConfig, err := config.LoadConfig(configFile)
	if err != nil {
		log.Fatal(err)
	}

	// Create Configuration objects for each factory
	managerConfiguration := new(webhook.ManagerConfiguration)
	certRotatorConfiguration := new(webhook.CertRotatorConfiguration)
	serverConfiguration := new(webhook.ServerConfiguration)
	handlerConfiguration := new(webhook.HandlerConfiguration)
	tivanInstrumentationConfiguration := new(tivan.TivanInstrumentationConfiguration)
	metricSubmitterConfiguration := new(tivan.MetricSubmitterConfiguration)
	tracerConfiguration := new(trace.TracerConfiguration)
	instrumentationConfiguration := new(instrumentation.InstrumentationProviderConfiguration)
	azdIdentityEnvAzureAuthorizerConfiguration := new(azureauth.EnvAzureAuthorizerConfiguration)
	kubeletIdentityEnvAzureAuthorizerConfiguration := new(azureauth.EnvAzureAuthorizerConfiguration)
	craneWrapper := new(registrywrappers.CraneWrapper)
	argBaseClient := argbase.New()

	// Create a map between configuration object and key in main config file
	keyConfigMap := map[string]interface{}{
		"Webhook.ManagerConfiguration":                            managerConfiguration,
		"Webhook.CertRotatorConfiguration":                        certRotatorConfiguration,
		"Webhook.ServerConfiguration":                             serverConfiguration,
		"Webhook.HandlerConfiguration":                            handlerConfiguration,
		"Instrumentation.tivan.TivanInstrumentationConfiguration": tivanInstrumentationConfiguration,
		"Instrumentation.trace.TracerConfiguration":               tracerConfiguration,
		"azdIdentity.EnvAzureAuthorizerConfiguration":             azdIdentityEnvAzureAuthorizerConfiguration,
		"kubeletIdentity.EnvAzureAuthorizerConfiguration":         kubeletIdentityEnvAzureAuthorizerConfiguration,
		"Acr.CraneWrappersConfiguration":		   			   	   &craneWrapper,
		"Arg.ArgBaseClient.RetryPolicyConfiguration": 			   &argBaseClient.Client,
	}

	for key, configObject := range keyConfigMap {
		// Unmarshal the relevant parts of appConfig's data to each of the configuration objects
		err = config.CreateSubConfiguration(AppConfig, key, configObject)
		if err != nil {
			log.Fatal("failed to load specific configuration data", err)
		}
	}

	// Create Tivan's instrumentation
	tivanInstrumentationResult, err := tivan.NewTivanInstrumentationResult(tivanInstrumentationConfiguration)
	if err != nil {
		log.Fatal("main.NewTivanInstrumentationResult", err)
	}

	// Create factories
	tracerFactory := tivan.NewTracerFactory(tracerConfiguration, tivanInstrumentationResult.Tracer)
	metricSubmitterFactory := tivan.NewMetricSubmitterFactory(metricSubmitterConfiguration, tivanInstrumentationResult.MetricSubmitter)
	instrumentationProviderFactory := instrumentation.NewInstrumentationProviderFactory(instrumentationConfiguration, tracerFactory, metricSubmitterFactory)
	instrumentationProvider, err := instrumentationProviderFactory.CreateInstrumentationProvider()
	if err != nil {
		log.Fatal("main.instrumentationProviderFactory.CreateInstrumentationProvider", err)
	}

	kubeletIdentityAuthorizerFactory := azureauth.NewEnvAzureAuthorizerFactory(azdIdentityEnvAzureAuthorizerConfiguration, new(azureauthwrappers.AzureAuthWrapper))
	kubeletIdentityAuthorizer, err := kubeletIdentityAuthorizerFactory.CreateARMAuthorizer()
	if err != nil {
		log.Fatal("main.kubeletIdentityAuthorizerFactory.NewEnvAzureAuthorizerFactory.CreateARMAuthorizer", err)
	}


	k8sclientconfig, err := k8sclientconfig.GetConfig()
	if err != nil {
		log.Fatal("main.k8sclientconfig.GetConfig", err)
	}
	clientK8s, err := kubernetes.NewForConfig(k8sclientconfig)
	if err != nil {
		log.Fatal("main.kubernetes.NewForConfig", err)
	}

	bearerAuthorizer, ok := kubeletIdentityAuthorizer.(azureauth.IBearerAuthorizer)
	if !ok {
		log.Fatal("main.kubeletIdentityAuthorizer.bearerAuthorizer type assertion", err)

	}

	acrTokenExchanger := registryauthazure.NewACRTokenExchanger(instrumentationProvider, &http.Client{})
	acrTokenProvider := registryauthazure.NewACRTokenProvider(instrumentationProvider, acrTokenExchanger, bearerAuthorizer)

	k8sKeychainFactory := crane.NewK8SKeychainFactory(instrumentationProvider, clientK8s)
	acrKeychainFactory := crane.NewACRKeychainFactory(instrumentationProvider, acrTokenProvider)

	// Registry Client
	registryClient := crane.NewCraneRegistryClient(instrumentationProvider, new(registrywrappers.CraneWrapper), acrKeychainFactory, k8sKeychainFactory)
	tag2digestResolver := tag2digest.NewTag2DigestResolver(instrumentationProvider, registryClient)

	// ARG
	azdIdentityAuthorizerFactory := azureauth.NewEnvAzureAuthorizerFactory(azdIdentityEnvAzureAuthorizerConfiguration, new(azureauthwrappers.AzureAuthWrapper))
	azdIdentityAuthorizer, err := azdIdentityAuthorizerFactory.CreateARMAuthorizer()
	if err != nil {
		log.Fatal("main.azdIdentityAuthorizerFactory.NewEnvAzureAuthorizerFactory.CreateARMAuthorizer", err)
	}
	argBaseClient.RetryDuration = argBaseClient.RetryDuration * time.Millisecond
	argBaseClient.Authorizer = azdIdentityAuthorizer
	argClient := arg.NewARGClient(instrumentationProvider, argBaseClient)
	argQueryGenerator, err := argqueries.CreateARGQueryGenerator(instrumentationProvider)
	if err != nil {
		log.Fatal("main.CreateARGQueryGenerator", err)
	}

	argDataProvider := arg.NewARGDataProvider(instrumentationProvider, argClient, argQueryGenerator)

	// Handler and azdSecinfoProvider
	azdSecInfoProvider := azdsecinfo.NewAzdSecInfoProvider(instrumentationProvider, argDataProvider, tag2digestResolver)
	handler := webhook.NewHandler(azdSecInfoProvider, handlerConfiguration, instrumentationProvider)

	// Manager and server
	managerFactory := webhook.NewManagerFactory(managerConfiguration, instrumentationProvider)
	certRotatorFactory := webhook.NewCertRotatorFactory(certRotatorConfiguration)
	serverFactory := webhook.NewServerFactory(serverConfiguration, managerFactory, certRotatorFactory, handler, instrumentationProvider)

	// Create Server
	server, err := serverFactory.CreateServer()
	if err != nil {
		log.Fatal("main.serverFactory.CreateServer", err)
	}
	// Run server
	if err = server.Run(); err != nil {
		log.Fatal("main.server.Run", err)
	}
}
