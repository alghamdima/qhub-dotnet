function HideTopbarPlugin()
{
	return {
		components: {
			Topbar: function () { return null }
		}
	}
}

const swaggerUi = SwaggerUIBundle({
	url: Qhub.OpenApi.SpecUrl,
	dom_id: '#swagger-ui',
	deepLinking: true,
	presets: [
		SwaggerUIBundle.presets.apis,
		SwaggerUIStandalonePreset
	],
	plugins: [
		SwaggerUIBundle.plugins.DownloadUrl,
		HideTopbarPlugin
	],
	layout: 'StandaloneLayout',
	docExpansion: "list"
});

window.ui = swaggerUi;
