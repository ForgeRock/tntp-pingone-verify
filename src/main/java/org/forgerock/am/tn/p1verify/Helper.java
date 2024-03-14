package org.forgerock.am.tn.p1verify;

import java.util.ArrayList;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.TextOutputCallback;

import org.forgerock.openam.auth.node.api.Action;

public class Helper {
	
	
	
	
	protected static Action getChoiceCallback() throws Exception {
		List<Callback> callbacks = new ArrayList<>();
		
		String[] options = {"Email", "SMS", "QR Code"};
        TextOutputCallback textOutputCallback = new TextOutputCallback(TextOutputCallback.INFORMATION, "Choose delivery method");
        callbacks.add(textOutputCallback);
        ConfirmationCallback deliveryChoiceCallback = new ConfirmationCallback("aaa", ConfirmationCallback.INFORMATION, options, 0);
        callbacks.add(deliveryChoiceCallback); 
		return Action.send(callbacks).build();
	}

}
