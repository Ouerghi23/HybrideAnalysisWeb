from django import forms

class AnalysisForm(forms.Form):
    input_value = forms.CharField(label='URL, IP ou Hash', required=False)
    file = forms.FileField(label='Ou téléverser un fichier', required=False)
    engine_choice = forms.ChoiceField(
        label='Moteur d\'analyse',
        choices=[('vt', 'VirusTotal'), ('otx', 'OTX (AlienVault)')],
        initial='vt'
    )

    def clean(self):
        cleaned_data = super().clean()
        input_value = cleaned_data.get('input_value')
        file = cleaned_data.get('file')

        if not input_value and not file:
            raise forms.ValidationError("Vous devez fournir une URL, une IP, un hash ou un fichier")
        return cleaned_data