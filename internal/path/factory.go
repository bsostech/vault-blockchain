package path

import (
	"github.com/hashicorp/vault/sdk/framework"
)

// GetPaths return paths
func GetPaths() []*framework.Path {
	return []*framework.Path{
		getPath(&createAccountPathConfig{}),
		getPath(&signTransactionPathConfig{}),
		getPath(&signPathConfig{}),
		getPath(&signBesuPrivateTransactionPathConfig{}),
		getPath(&encryptPathConfig{}),
		getPath(&decryptPathConfig{}),
	}
}

func getPath(c config) *framework.Path {
	return &framework.Path{
		Pattern:        c.getPattern(),
		HelpSynopsis:   c.getHelpSynopsis(),
		Fields:         c.getFields(),
		ExistenceCheck: c.getExistenceFunc(),
		Callbacks:      c.getCallbacks(),
	}
}
