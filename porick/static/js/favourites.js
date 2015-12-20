function setupFavouritesClickHandlers() {
    /**
     * Assign click handlers to all favourite buttons.
     */
    $('.favourite').click(function() {
    	var quote_id = $(this).data('quote_id');
        if($(this).hasClass('favourited')) {
        	removeFavourite(quote_id, $(this));
        } else {
        	addFavourite(quote_id, $(this));
        }
    });
}

function removeFavourite(quote_id, button) {
	$.ajax({
        url: '/api/v1/quotes/'+quote_id+'/favourite',
        type: 'DELETE',
        success: function(data, status, jqXHR){
            button.removeClass('success error favourited');
            $(button.children('i')[0]).attr('class', 'icon-star-empty');
        }
    });
}

function addFavourite(quote_id, button) {
	$.ajax({
        url: '/api/v1/quotes/'+quote_id+'/favourite',
        type: 'POST',
        success: function(data, status, jqXHR){
            button.addClass(data['status'] + ' favourited');
            $(button.children('i')[0]).attr('class', 'icon-star');
        }
    });
}
