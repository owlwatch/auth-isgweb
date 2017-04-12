<div class="wrap">
  <h2>ISGweb for iMIS Settings</h2>
  <form action="<?php echo admin_url('network/settings.php?page=isgweb-auth-settings') ?>" method="post">
    <?php
    wp_nonce_field('isgweb-auth');
    ?>
    <table class="form-table">
      <?php
      foreach( $form->get_fields() as $field ) echo $field->get_html();
      ?>
    </table>
    <p class="submit">
      <input type="submit" name="submit" id="submit" class="button button-primary" value="Save Changes" />
    </p>
  </form>
</div>